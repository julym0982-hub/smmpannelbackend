// ════════════════════════════════════════════════════════════════
//  web.js  —  SMM Panel Backend (Single File)
//  Stack  : Node.js + Express + MongoDB (Mongoose) + JWT + bcrypt
//  Host   : Render.com
// ════════════════════════════════════════════════════════════════

"use strict";

require("dotenv").config();
const express  = require("express");
const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");

// ──────────────────────────────────────────────────────────────
//  ENV
// ──────────────────────────────────────────────────────────────
const PORT        = process.env.PORT        || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET  || "change_me_in_env";
const JWT_EXPIRES = "7d";
const SALT_ROUNDS = 12;

if (!MONGODB_URI) {
  console.error("❌  MONGODB_URI is not set in .env");
  process.exit(1);
}

// ──────────────────────────────────────────────────────────────
//  EXPRESS
// ──────────────────────────────────────────────────────────────
const app = express();

// ── CORS (manual headers — most reliable on Render) ───────────
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = [
    "https://smmpannelfrontend.vercel.app",
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
  ];

  if (!origin || allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");

  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.json());

// ──────────────────────────────────────────────────────────────
//  USER MODEL
//  ⚠️  NO pre-save hook — we hash manually in each route
//      to prevent accidental double-hashing
// ──────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    name:  { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true },
    password:     { type: String, required: true },
    balance:      { type: Number, default: 0 },
    balanceSpent: { type: Number, default: 0 },
    totalOrders:  { type: Number, default: 0 },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ──────────────────────────────────────────────────────────────
//  HELPERS
// ──────────────────────────────────────────────────────────────
const signToken = (id) =>
  jwt.sign({ id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

const safeUser = (u) => ({
  id:           u._id,
  name:         u.name,
  email:        u.email,
  balance:      u.balance,
  balanceSpent: u.balanceSpent,
  totalOrders:  u.totalOrders,
});

// Normalize email — always lowercase + trim before DB ops
const normalizeEmail = (email) => (email || "").toLowerCase().trim();

// ──────────────────────────────────────────────────────────────
//  AUTH MIDDLEWARE
// ──────────────────────────────────────────────────────────────
function authGuard(req, res, next) {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "No token provided" });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ──────────────────────────────────────────────────────────────
//  ROUTES
// ──────────────────────────────────────────────────────────────

// Health
app.get("/", (_req, res) =>
  res.json({ status: "🚀 SMM Panel API is running", time: new Date() })
);

// ── SIGNUP ────────────────────────────────────────────────────
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, password } = req.body;
    const email = normalizeEmail(req.body.email);

    if (!name || !email || !password)
      return res.status(400).json({ message: "Please fill in all fields" });

    if (password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    if (await User.findOne({ email }))
      return res.status(400).json({ message: "Email is already registered" });

    // ✅ Hash once — explicitly here, no pre-save hook
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = await User.create({ name, email, password: hashedPassword });

    console.log(`✅ Signup: ${email}`);
    return res.status(201).json({
      message: "Account created successfully",
      token:   signToken(user._id),
      user:    safeUser(user),
    });
  } catch (err) {
    console.error("Signup error:", err.message);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  try {
    const { password } = req.body;
    const email = normalizeEmail(req.body.email);

    if (!email || !password)
      return res.status(400).json({ message: "Please fill in all fields" });

    const user = await User.findOne({ email });
    if (!user) {
      console.log(`❌ Login failed — email not found: ${email}`);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // ✅ Compare plaintext against the single-hashed DB password
    const matched = await bcrypt.compare(password, user.password);
    if (!matched) {
      console.log(`❌ Login failed — wrong password for: ${email}`);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    console.log(`✅ Login: ${email}`);
    return res.json({
      message: "Login successful",
      token:   signToken(user._id),
      user:    safeUser(user),
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── RESET PASSWORD ────────────────────────────────────────────
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { newPassword } = req.body;
    const email = normalizeEmail(req.body.email);

    if (!email || !newPassword)
      return res.status(400).json({ message: "Email and new password are required" });

    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "No account found with this email" });

    // ✅ Hash once then use updateOne — bypasses pre-save hook completely
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await User.updateOne({ email }, { $set: { password: hashedPassword } });

    console.log(`✅ Password reset: ${email}`);
    return res.json({ message: "Password reset successfully. You can now log in." });
  } catch (err) {
    console.error("Reset-password error:", err.message);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── GET ME (protected) ────────────────────────────────────────
app.get("/api/auth/me", authGuard, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.json(safeUser(user));
  } catch (err) {
    console.error("Me error:", err.message);
    return res.status(500).json({ message: "Server error" });
  }
});

// ── 404 ───────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ message: "Route not found" }));

// ── Global error handler ──────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error("Unhandled:", err.message);
  res.status(500).json({ message: "Internal server error" });
});

// ──────────────────────────────────────────────────────────────
//  START
// ──────────────────────────────────────────────────────────────
mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () => console.log(`🚀  Listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌  MongoDB failed:", err.message);
    process.exit(1);
  });
