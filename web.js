"use strict";
require("dotenv").config();

const express  = require("express");
const cors     = require("cors");
const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");

const PORT        = process.env.PORT        || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET  || "change_me";

if (!MONGODB_URI) { console.error("❌  MONGODB_URI missing"); process.exit(1); }

const app = express();

/* ══════════════════════════════════════════════════════════
   CORS  —  cors npm package
══════════════════════════════════════════════════════════ */
app.use(cors({
  origin: [
    "https://smmpannelfrontend.vercel.app",   // production frontend
    /\.vercel\.app$/,                          // all Vercel preview deploys
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
  ],
  methods:        ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials:    true,
}));

app.use(express.json());

/* ══════════════════════════════════════════════════════════
   USER SCHEMA
══════════════════════════════════════════════════════════ */
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:     { type: String, required: true },
  balance:      { type: Number, default: 0 },
  balanceSpent: { type: Number, default: 0 },
  totalOrders:  { type: Number, default: 0 },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ══════════════════════════════════════════════════════════
   HELPERS
══════════════════════════════════════════════════════════ */
const makeToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });

const safeUser = (u) => ({
  id:           u._id,
  name:         u.name,
  email:        u.email,
  balance:      u.balance,
  balanceSpent: u.balanceSpent,
  totalOrders:  u.totalOrders,
  createdAt:    u.createdAt,
});

const normEmail = (e) => String(e || "").toLowerCase().trim();

/* Auth middleware */
function guard(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }
  try {
    req.uid = jwt.verify(header.slice(7), JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ message: "Token invalid or expired" });
  }
}

/* ══════════════════════════════════════════════════════════
   ROUTES
══════════════════════════════════════════════════════════ */

/* Health check */
app.get("/", (_, res) => res.json({ status: "running", time: new Date() }));

/* ── SIGNUP ──────────────────────────────────────────────── */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, password } = req.body;
    const email = normEmail(req.body.email);

    if (!name || !email || !password)
      return res.status(400).json({ message: "Please fill in all fields" });
    if (password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (await User.findOne({ email }))
      return res.status(400).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hash });

    console.log("[SIGNUP OK]", email);
    res.status(201).json({
      message: "Account created successfully",
      token:   makeToken(user._id),
      user:    safeUser(user),
    });
  } catch (e) {
    console.error("[SIGNUP ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ── LOGIN  (email OR username) ──────────────────────────── */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { password } = req.body;
    const input = String(req.body.email || req.body.username || "").trim();

    if (!input || !password)
      return res.status(400).json({ message: "Please fill in all fields" });

    const user = await User.findOne({
      $or: [
        { email: input.toLowerCase() },
        { name:  { $regex: `^${input}$`, $options: "i" } },
      ],
    });

    if (!user)
      return res.status(401).json({ message: "Invalid username or password" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res.status(401).json({ message: "Invalid username or password" });

    console.log("[LOGIN OK]", user.email);
    res.json({
      message: "Login successful",
      token:   makeToken(user._id),
      user:    safeUser(user),
    });
  } catch (e) {
    console.error("[LOGIN ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ── RESET PASSWORD ──────────────────────────────────────── */
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { newPassword } = req.body;
    const email = normEmail(req.body.email);

    if (!email || !newPassword)
      return res.status(400).json({ message: "Email and new password are required" });
    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "No account found with this email" });

    const hash = await bcrypt.hash(newPassword, 12);
    await User.updateOne({ email }, { $set: { password: hash } });

    console.log("[RESET OK]", email);
    res.json({ message: "Password reset successfully. You can now log in." });
  } catch (e) {
    console.error("[RESET ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ── ME  (current user info + balance) ───────────────────── */
app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const user = await User.findById(req.uid).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(safeUser(user));
  } catch (e) {
    console.error("[ME ERR]", e.message);
    res.status(500).json({ message: "Server error" });
  }
});

/* ── CHANGE PASSWORD ─────────────────────────── */
app.post("/api/auth/change-password", guard, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: "Both fields are required" });
    if (newPassword.length < 6)
      return res.status(400).json({ message: "New password must be at least 6 characters" });

    const user = await User.findById(req.uid);
    if (!user) return res.status(404).json({ message: "User not found" });

    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok)
      return res.status(401).json({ message: "Current password is incorrect" });

    const hash = await bcrypt.hash(newPassword, 12);
    await User.updateOne({ _id: req.uid }, { $set: { password: hash } });

    console.log("[CHPW OK]", user.email);
    res.json({ message: "Password changed successfully" });
  } catch (e) {
    console.error("[CHPW ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* 404 */
app.use((_, res) => res.status(404).json({ message: "Route not found" }));

/* ══════════════════════════════════════════════════════════
   START
══════════════════════════════════════════════════════════ */
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () => console.log(`🚀  Server running on port ${PORT}`));
  })
  .catch(e => {
    console.error("❌  MongoDB connection failed:", e.message);
    process.exit(1);
  });
