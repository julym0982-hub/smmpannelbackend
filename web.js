"use strict";
require("dotenv").config();
const express  = require("express");
const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");

const PORT        = process.env.PORT       || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET || "change_me";

if (!MONGODB_URI) { console.error("❌ MONGODB_URI missing"); process.exit(1); }

const app = express();

/* ── CORS: allow ALL *.vercel.app + localhost ─────────────── */
app.use((req, res, next) => {
  const o = req.headers.origin || "";
  if (o.endsWith(".vercel.app") || o.includes("localhost") || o.includes("127.0.0.1") || !o) {
    res.setHeader("Access-Control-Allow-Origin",      o || "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods",     "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers",     "Content-Type,Authorization");
  }
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.json());

/* ── User Schema — NO pre-save hook ──────────────────────── */
const User = mongoose.model("User", new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true },
  password:     { type: String, required: true },
  balance:      { type: Number, default: 0 },
  balanceSpent: { type: Number, default: 0 },
  totalOrders:  { type: Number, default: 0 },
}, { timestamps: true }));

/* ── Helpers ─────────────────────────────────────────────── */
const token = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });
const safe  = (u)  => ({ id: u._id, name: u.name, email: u.email,
                          balance: u.balance, balanceSpent: u.balanceSpent,
                          totalOrders: u.totalOrders });
const norm  = (e)  => String(e || "").toLowerCase().trim();

function guard(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ message: "No token" });
  try { req.uid = jwt.verify(h.slice(7), JWT_SECRET).id; next(); }
  catch { res.status(401).json({ message: "Invalid token" }); }
}

/* ═══════════════════════════════════════════════════════════
   ROUTES
═══════════════════════════════════════════════════════════ */

/* Health */
app.get("/", (_, res) => res.json({ status: "running", time: new Date() }));

/* ── DEBUG: test bcrypt directly ────────────────────────── */
/* Visit: https://smmpannelbackend.onrender.com/api/debug/hash */
app.get("/api/debug/hash", async (_, res) => {
  const plain  = "testpass123";
  const hashed = await bcrypt.hash(plain, 12);
  const match  = await bcrypt.compare(plain, hashed);
  res.json({ plain, hashed, bcrypt_compare_result: match, bcryptjs_version: require("bcryptjs/package.json").version });
});

/* ── DEBUG: check a stored user's password hash ─────────── */
/* Visit: https://smmpannelbackend.onrender.com/api/debug/user?email=xx@xx.com */
app.get("/api/debug/user", async (req, res) => {
  try {
    const email = norm(req.query.email);
    const u = await User.findOne({ email });
    if (!u) return res.json({ found: false, email });
    res.json({ found: true, email: u.email, password_hash_preview: u.password.slice(0, 20) + "...", starts_with_2a: u.password.startsWith("$2a$") || u.password.startsWith("$2b$") });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ── SIGNUP ──────────────────────────────────────────────── */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, password } = req.body;
    const email = norm(req.body.email);

    if (!name || !email || !password) return res.status(400).json({ message: "Please fill all fields" });
    if (password.length < 6)          return res.status(400).json({ message: "Password min 6 characters" });
    if (await User.findOne({ email })) return res.status(400).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hash });
    console.log("[SIGNUP OK]", email, "| hash:", hash.slice(0,10));

    res.status(201).json({ message: "Account created", token: token(user._id), user: safe(user) });
  } catch (e) { console.error("[SIGNUP ERR]", e.message); res.status(500).json({ message: "Server error: " + e.message }); }
});

/* ── LOGIN (email OR username) ───────────────────────────── */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { password } = req.body;
    const input = String(req.body.email || "").trim(); // username or email

    if (!input || !password) return res.status(400).json({ message: "Please fill all fields" });

    // Search by email (lowercase) OR by name (username, case-insensitive)
    const user = await User.findOne({
      $or: [
        { email: input.toLowerCase() },
        { name: { $regex: `^${input}$`, $options: "i" } },
      ],
    });

    if (!user) {
      console.log("[LOGIN FAIL] not found:", input);
      return res.status(401).json({ message: "Invalid username or password" });
    }

    console.log("[LOGIN ATTEMPT]", input, "| stored hash:", user.password.slice(0,10));
    const ok = await bcrypt.compare(password, user.password);
    console.log("[LOGIN COMPARE]", ok ? "MATCH ✅" : "NO MATCH ❌");

    if (!ok) return res.status(401).json({ message: "Invalid username or password" });

    res.json({ message: "Login successful", token: token(user._id), user: safe(user) });
  } catch (e) { console.error("[LOGIN ERR]", e.message); res.status(500).json({ message: "Server error: " + e.message }); }
});

/* ── RESET PASSWORD ──────────────────────────────────────── */
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { newPassword } = req.body;
    const email = norm(req.body.email);

    if (!email || !newPassword) return res.status(400).json({ message: "Email and new password required" });
    if (newPassword.length < 6)  return res.status(400).json({ message: "Password min 6 characters" });

    if (!await User.findOne({ email })) return res.status(404).json({ message: "No account with this email" });

    const hash = await bcrypt.hash(newPassword, 12);
    await User.updateOne({ email }, { $set: { password: hash } }); // updateOne = no pre-save hook
    console.log("[RESET OK]", email, "| new hash:", hash.slice(0,10));

    res.json({ message: "Password reset successfully. You can now log in." });
  } catch (e) { console.error("[RESET ERR]", e.message); res.status(500).json({ message: "Server error: " + e.message }); }
});

/* ── ME ──────────────────────────────────────────────────── */
app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const u = await User.findById(req.uid).select("-password");
    if (!u) return res.status(404).json({ message: "User not found" });
    res.json(safe(u));
  } catch (e) { res.status(500).json({ message: "Server error" }); }
});

/* ── Start ───────────────────────────────────────────────── */
mongoose.connect(MONGODB_URI)
  .then(() => { console.log("✅ MongoDB connected"); app.listen(PORT, () => console.log(`🚀 Port ${PORT}`)); })
  .catch(e  => { console.error("❌ MongoDB:", e.message); process.exit(1); });
