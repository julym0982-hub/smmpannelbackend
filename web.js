"use strict";

require("dotenv").config();
const express  = require("express");
const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");

const PORT        = process.env.PORT        || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET  || "change_me";

if (!MONGODB_URI) { console.error("MONGODB_URI missing"); process.exit(1); }

const app = express();

// ═══════════════════════════════════════════════
//  CORS — allow ALL *.vercel.app + localhost
// ═══════════════════════════════════════════════
app.use((req, res, next) => {
  const origin = req.headers.origin || "";

  const isAllowed =
    origin.endsWith(".vercel.app") ||
    origin.startsWith("http://localhost") ||
    origin.startsWith("http://127.0.0.1") ||
    origin === "";

  if (isAllowed) {
    res.setHeader("Access-Control-Allow-Origin",      origin || "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods",     "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers",     "Content-Type,Authorization");
  }

  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.json());

// ═══════════════════════════════════════════════
//  USER MODEL  (NO pre-save hook — prevent double hash)
// ═══════════════════════════════════════════════
const User = mongoose.model("User", new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true },
  password:     { type: String, required: true },
  balance:      { type: Number, default: 0 },
  balanceSpent: { type: Number, default: 0 },
  totalOrders:  { type: Number, default: 0 },
}, { timestamps: true }));

// ═══════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════
const makeToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });
const pub       = (u)  => ({ id: u._id, name: u.name, email: u.email,
                              balance: u.balance, balanceSpent: u.balanceSpent,
                              totalOrders: u.totalOrders });
const norm      = (e)  => (e || "").toLowerCase().trim();

function guard(req, res, next) {
  const h = (req.headers.authorization || "");
  if (!h.startsWith("Bearer ")) return res.status(401).json({ message: "No token" });
  try { req.uid = jwt.verify(h.slice(7), JWT_SECRET).id; next(); }
  catch { res.status(401).json({ message: "Invalid token" }); }
}

// ═══════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════
app.get("/", (_, res) => res.json({ ok: true, time: new Date() }));

// SIGNUP
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, password } = req.body;
    const email = norm(req.body.email);

    if (!name || !email || !password)
      return res.status(400).json({ message: "Please fill all fields" });
    if (password.length < 6)
      return res.status(400).json({ message: "Password min 6 characters" });
    if (await User.findOne({ email }))
      return res.status(400).json({ message: "Email already registered" });

    // Hash HERE — only once, no pre-save hook
    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hash });

    console.log("[SIGNUP OK]", email);
    res.status(201).json({ message: "Account created", token: makeToken(user._id), user: pub(user) });
  } catch (e) {
    console.error("[SIGNUP ERR]", e.message);
    res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { password } = req.body;
    const email = norm(req.body.email);

    if (!email || !password)
      return res.status(400).json({ message: "Please fill all fields" });

    const user = await User.findOne({ email });
    if (!user) {
      console.log("[LOGIN FAIL] not found:", email);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      console.log("[LOGIN FAIL] wrong pw:", email);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    console.log("[LOGIN OK]", email);
    res.json({ message: "Login successful", token: makeToken(user._id), user: pub(user) });
  } catch (e) {
    console.error("[LOGIN ERR]", e.message);
    res.status(500).json({ message: "Server error" });
  }
});

// RESET PASSWORD
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { newPassword } = req.body;
    const email = norm(req.body.email);

    if (!email || !newPassword)
      return res.status(400).json({ message: "Email and new password required" });
    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password min 6 characters" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "No account with this email" });

    // Hash once, then updateOne (skips pre-save hook entirely)
    const hash = await bcrypt.hash(newPassword, 12);
    await User.updateOne({ email }, { $set: { password: hash } });

    console.log("[RESET OK]", email);
    res.json({ message: "Password reset successfully. You can now log in." });
  } catch (e) {
    console.error("[RESET ERR]", e.message);
    res.status(500).json({ message: "Server error" });
  }
});

// ME (protected)
app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const u = await User.findById(req.uid).select("-password");
    if (!u) return res.status(404).json({ message: "User not found" });
    res.json(pub(u));
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

// ═══════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(PORT, () => console.log(`🚀 Port ${PORT}`));
  })
  .catch(e => { console.error("❌ MongoDB:", e.message); process.exit(1); });
