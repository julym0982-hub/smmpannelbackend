"use strict";
require("dotenv").config();

const express      = require("express");
const cors         = require("cors");
const mongoose     = require("mongoose");
const bcrypt       = require("bcryptjs");
const jwt          = require("jsonwebtoken");
const axios        = require("axios");
const multer       = require("multer");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const cookieParser  = require("cookie-parser");
const cron          = require("node-cron");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) =>
    file.mimetype.startsWith("image/") ? cb(null, true) : cb(new Error("Images only")),
});

/* ══════════════════════════════════════════════════════════
   ENV VARS
══════════════════════════════════════════════════════════ */
const PORT        = process.env.PORT        || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET;
const JAP_API_KEY   = process.env.JAP_API_KEY   || "";
const IMGBB_API_KEY = process.env.IMGBB_API_KEY || "";
const ADMIN_EMAILS  = (process.env.ADMIN_EMAILS || "")
  .split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
const JAP_API_URL = process.env.JAP_API_URL || "https://justanotherpanel.com/api/v2";
const MMK_RATE    = parseFloat(process.env.MMK_RATE || "4500");
const MARKUP         = parseFloat(process.env.MARKUP   || "1.2");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(u => u.trim()).filter(Boolean);

if (!MONGODB_URI) { console.error("❌  MONGODB_URI missing"); process.exit(1); }
if (!JWT_SECRET)  { console.error("❌  JWT_SECRET missing");  process.exit(1); }
if (!JAP_API_KEY)    console.warn("⚠️  JAP_API_KEY not set");
if (!IMGBB_API_KEY)  console.warn("⚠️  IMGBB_API_KEY not set — file upload won't work");

const app = express();
app.set('trust proxy', 1);          // Required for Render proxy
app.use(cookieParser());             // Parse HttpOnly JWT cookie

/* ══════════════════════════════════════════════════════════
   SECURITY MIDDLEWARE
══════════════════════════════════════════════════════════ */

// ── Helmet — secure HTTP headers ──────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://api.imgbb.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc:     ["'self'", "data:", "https://i.ibb.co", "https://*.ibb.co"],
      connectSrc: ["'self'", "https://justanotherpanel.com", "https://api.imgbb.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ── CORS — restrict to known origins ──────────────────────
const VERCEL_ORIGINS = ALLOWED_ORIGINS.length > 0
  ? ALLOWED_ORIGINS
  : [/\.vercel\.app$/, "http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500"];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);   // same-origin / Postman
    const allowed = Array.isArray(VERCEL_ORIGINS) ? VERCEL_ORIGINS : [VERCEL_ORIGINS];
    const ok = allowed.some(o =>
      typeof o === "string" ? o === origin : o.test(origin)
    );
    if (ok) return cb(null, true);
    console.warn("[CORS] Blocked:", origin);
    return cb(new Error("CORS policy: origin not allowed"));
  },
  methods:        ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials:    true,
}));

// ── Body parsing & NoSQL injection prevention ─────────────
app.use(express.json({ limit: "2mb" }));
app.use(mongoSanitize({             // strip $ and . from user input
  replaceWith: "_",
  onSanitize: ({ req, key }) => {
    console.warn(`[SECURITY] Sanitized field "${key}" from ${req.ip}`);
  },
}));

/* ── Rate limiters ──────────────────────────────────────────
   Brute-force protection for auth endpoints                  */
const authLimiter = rateLimit({
  windowMs:         15 * 60 * 1000,   // 15 minutes
  max:              20,                // 20 attempts per window per IP
  standardHeaders:  true,
  legacyHeaders:    false,
  message:          { message: "Too many login attempts. Please try again in 15 minutes." },
  handler(req, res, next, options) {
    console.warn(`[RATE LIMIT] Auth limit hit: ${req.ip}`);
    res.status(429).json(options.message);
  },
});

const apiLimiter = rateLimit({
  windowMs:  1 * 60 * 1000,    // 1 minute
  max:       60,                // 60 requests/min per IP
  standardHeaders: true,
  legacyHeaders:   false,
  message:   { message: "Too many requests. Please slow down." },
});

app.use("/api/", apiLimiter);   // apply globally

/* ── Request logger (lightweight) ───────────────────────── */
const isProd = process.env.NODE_ENV === "production";
app.use((req, _, next) => {
  if (!isProd) console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

/* ══════════════════════════════════════════════════════════
   SCHEMAS
══════════════════════════════════════════════════════════ */
const userSchema = new mongoose.Schema({
  name:          { type: String, required: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:      { type: String, required: true },
  balance:       { type: Number, default: 0 },
  balanceSpent:  { type: Number, default: 0 },
  totalOrders:   { type: Number, default: 0 },
  isAdmin:       { type: Boolean, default: false },
  loginAttempts: { type: Number, default: 0 },          // Brute-force protection
  lockUntil:     { type: Date,   default: null },        // Account lockout timestamp
  backupCodes:   [{
    hash: { type: String, required: true },
    used: { type: Boolean, default: false },
  }],
}, { timestamps: true });

// ── Performance indexes ────────────────────────────────
// email index already created by unique:true in schema
userSchema.index({ name: 1 });

const User = mongoose.model("User", userSchema);

/* ── FundRequest (Deposit) ────────────────────────────────── */
const fundRequestSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  transactionId: { type: String, required: true, trim: true },
  screenshotUrl: { type: String, required: true },
  amount:        { type: Number, default: 0 },       // user-specified or admin-set
  status:        { type: String,
                   enum: ["Pending","Approved","Rejected"],
                   default: "Pending" },
  adminNotes:    { type: String, default: "" },
}, { timestamps: true });
fundRequestSchema.index({ userId: 1, createdAt: -1 });
fundRequestSchema.index({ status: 1 });
const FundRequest = mongoose.model("FundRequest", fundRequestSchema);

/* ── ServiceCache Schema — stores JAP services in MongoDB ─
   Lets us serve services INSTANTLY from DB,
   instead of calling JAP API on every request.            */
const serviceCacheSchema = new mongoose.Schema({
  service_id:   { type: String, required: true, unique: true },
  name:         { type: String, default: "" },
  type:         { type: String, default: "Default" },
  category:     { type: String, default: "Other" },
  rate:         { type: String, default: "0" },
  min:          { type: String, default: "10" },
  max:          { type: String, default: "10000000" },
  refill:       { type: Boolean, default: false },
  cancel:       { type: Boolean, default: false },
  average_time: { type: String, default: null },
}, { timestamps: true });
serviceCacheSchema.index({ category: 1 });
const ServiceCache = mongoose.model("ServiceCache", serviceCacheSchema);



const orderSchema = new mongoose.Schema({
  user:            { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  providerOrderId: { type: Number, default: null },   // JAP order ID
  serviceId:       { type: String, required: true },
  serviceName:     { type: String, default: "" },
  category:        { type: String, default: "" },
  link:            { type: String, required: true },
  quantity:        { type: Number, required: true },
  chargeMMK:       { type: Number, required: true },
  chargeUSD:       { type: Number, default: 0 },
  status:          { type: String, default: "Pending" },  // JAP: Pending | In progress | Completed | Partial | Canceled
  startCount:      { type: String, default: "0" },        // JAP: start_count
  remains:         { type: Number, default: 0 },          // JAP: remains
  providerError:   { type: String, default: null },
}, { timestamps: true });
// ── Performance indexes ────────────────────────────────
orderSchema.index({ user: 1, createdAt: -1 });
orderSchema.index({ user: 1, status: 1 });
const Order = mongoose.model("Order", orderSchema);

/* ══════════════════════════════════════════════════════════
   HELPERS
══════════════════════════════════════════════════════════ */
const makeToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });

const safeUser = (u) => ({
  id:           u._id,
  name:         sanitizeStr(u.name),
  email:        sanitizeStr(u.email),
  balance:      u.balance       || 0,
  balanceSpent: u.balanceSpent  || 0,
  totalOrders:  u.totalOrders   || 0,
  createdAt:    u.createdAt,
  isAdmin:      !!(u.isAdmin || ADMIN_EMAILS.includes((u.email||"").toLowerCase())),
  // Never expose: password, loginAttempts, lockUntil
});

/* ── Sanitize output strings (prevent XSS via API responses) */
function sanitizeStr(s) {
  if (typeof s !== "string") return s;
  return s.replace(/[<>&"']/g, c => ({
    "<":"&lt;", ">":"&gt;", "&":"&amp;", '"':"&quot;", "'":"&#x27;",
  }[c]));
}

const normEmail = (e) => String(e || "").toLowerCase().trim();

/* ── Input validation ─────────────────────────────────────*/
const isEmail   = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const isMongoId = (id) => /^[0-9a-fA-F]{24}$/.test(String(id || ""));


/* ── Set JWT as HttpOnly cookie ─────────────────────────*/
function setAuthCookie(res, token) {
  const prod = process.env.NODE_ENV === "production";
  res.cookie("smm_token", token, {
    httpOnly: true,
    secure:   prod,                       // SameSite=none requires secure=true
    sameSite: prod ? "none" : "lax",     // cross-origin prod / lax localhost
    maxAge:   7 * 24 * 60 * 60 * 1000,
  });
}

/* ── Generate 8 one-time backup codes ───────────────────*/
async function generateBackupCodes() {
  const nodeCrypto = require("crypto");
  const raw = Array.from({ length: 8 }, () =>
    nodeCrypto.randomBytes(5).toString("hex").toUpperCase()
  );
  const hashed = await Promise.all(raw.map(c => bcrypt.hash(c, 10)));
  return {
    raw,
    stored: hashed.map(hash => ({ hash, used: false })),
  };
}

/* ── Auth middleware ─────────────────────────────────────*/
function guard(req, res, next) {
  try {
    const cookieToken = req.cookies && req.cookies.smm_token;
    const authHeader  = req.headers["authorization"] || "";
    const parts       = authHeader.trim().split(/\s+/);
    const headerToken = (parts.length === 2 && parts[0].toLowerCase() === "bearer")
      ? parts[1] : (parts.length === 1 && parts[0] !== "bearer" ? parts[0] : "");
    const token = cookieToken || headerToken;
    if (!token) return res.status(401).json({ message: "Not authenticated. Please log in." });
    req.uid = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError")
      return res.status(401).json({ message: "Session expired. Please log in again." });
    return res.status(401).json({ message: "Invalid session. Please log in again." });
  }
}


/* ── Admin guard ──────────────────────────────────────────*/
async function adminGuard(req, res, next) {
  try {
    // Read JWT from HttpOnly cookie first, then Authorization header as fallback
    const cookieToken = req.cookies && req.cookies.smm_token;
    const h           = req.headers["authorization"] || "";
    const parts       = h.trim().split(/\s+/);
    const headerToken = parts.length === 2 && parts[0].toLowerCase() === "bearer"
      ? parts[1] : (parts[0] !== "bearer" ? parts[0] : "");
    const token = cookieToken || headerToken;

    if (!token) return res.status(401).json({ message: "Not authenticated" });
    req.uid = jwt.verify(token, JWT_SECRET).id;
    const user = await User.findById(req.uid);
    if (!user) return res.status(404).json({ message: "User not found" });
    const isAdmin = user.isAdmin || ADMIN_EMAILS.includes(user.email.toLowerCase());
    if (!isAdmin) return res.status(403).json({ message: "Admin access required" });
    req.adminUser = user;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Session expired. Please log in again." });
  }
}

/* ── ImgBB upload (free image hosting, no disk needed) ────*/
async function uploadToImgBB(buffer) {
  if (!IMGBB_API_KEY) throw new Error("IMGBB_API_KEY not set on server");
  const params = new URLSearchParams();
  params.append("key",   IMGBB_API_KEY);
  params.append("image", buffer.toString("base64"));
  const { data } = await axios.post("https://api.imgbb.com/1/upload", params.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 30000,
  });
  if (!data.success) throw new Error("ImgBB upload failed: " + JSON.stringify(data));
  return data.data.url;
}

/* ══════════════════════════════════════════════════════════
   JAP API HELPER
   ─────────────────────────────────────────────────────────
   JAP Docs: POST application/x-www-form-urlencoded
   key      → API key
   action   → add | services | status | refill | cancel | balance
   order    → single order ID
   orders   → multiple order IDs (comma-separated) for status/cancel/refill
══════════════════════════════════════════════════════════ */
async function japAPI(params, _attempt = 0) {
  const MAX_ATTEMPTS = 4;          // 4 attempts total
  const TIMEOUTS     = [30000, 40000, 50000, 60000]; // grow per attempt
  const DELAYS       = [2000,  4000,  8000];          // backoff between retries

  const payload = new URLSearchParams();
  payload.append("key",    JAP_API_KEY);
  payload.append("action", params.action);

  if (params.action === "add") {
    payload.append("service",  String(params.service));
    payload.append("link",     String(params.link));
    payload.append("quantity", String(params.quantity));
    if (params.runs)     payload.append("runs",     String(params.runs));
    if (params.interval) payload.append("interval", String(params.interval));
    if (params.comments) payload.append("comments", String(params.comments));
  }
  if (["status", "refill"].includes(params.action) && params.order)
    payload.append("order", String(params.order));
  if (params.orders)
    payload.append("orders", String(params.orders));

  console.log(`[JAP] ${params.action.toUpperCase()} attempt ${_attempt + 1}/${MAX_ATTEMPTS}`);

  try {
    const { status, data } = await axios.post(
      JAP_API_URL,
      payload.toString(),
      {
        headers: {
          "Content-Type":     "application/x-www-form-urlencoded",
          "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept":           "application/json, text/javascript, */*; q=0.01",
          "Accept-Language":  "en-US,en;q=0.9",
          "Accept-Encoding":  "gzip, deflate, br",
          "Referer":          "https://justanotherpanel.com/",
          "Origin":           "https://justanotherpanel.com",
          "X-Requested-With": "XMLHttpRequest",
          "Connection":       "keep-alive",
        },
        timeout: TIMEOUTS[_attempt] || 60000,
      }
    );
    if (data && data.error) throw new Error(String(data.error));
    return data;

  } catch (err) {
    const isTimeout  = !!err.request && !err.response;
    const isRetryHTTP = err.response && [429, 503, 502, 504].includes(err.response.status);

    if ((isTimeout || isRetryHTTP) && _attempt + 1 < MAX_ATTEMPTS) {
      const delay = DELAYS[_attempt] || 8000;
      console.warn(`[JAP] Attempt ${_attempt + 1} failed (${isTimeout ? "timeout" : err.response.status}). Retrying in ${delay / 1000}s...`);
      await new Promise(r => setTimeout(r, delay));
      return japAPI(params, _attempt + 1);
    }

    // Final failure
    if (err.response) {
      const msg = err.response.data?.error || err.response.data?.message || `HTTP ${err.response.status}`;
      throw new Error(msg);
    }
    if (isTimeout) throw new Error("ဆာဗာနှင့် ဆက်သွယ်မရပါ — ခဏစောင့်ပြီး ထပ်ကြိုးစားပါ");
    throw new Error(err.message.replace(/\[JAP\]\s*/gi, "").trim() || "Unknown error");
  }
}

/* ══════════════════════════════════════════════════════════
   ROUTES — AUTH
══════════════════════════════════════════════════════════ */
app.get("/", (_, res) => res.json({ status: "running", provider: "JAP", time: new Date() }));

app.post("/api/auth/signup", authLimiter, async (req, res) => {
  try {
    const { name, password } = req.body;
    const email = normEmail(req.body.email);
    if (!name || !email || !password)
      return res.status(400).json({ message: "Please fill in all fields" });
    if (password.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (await User.findOne({ email }))
      return res.status(400).json({ message: "An account with this email already exists" });
    const { raw: backupCodesRaw, stored: backupCodesStored } = await generateBackupCodes();
    const user = await User.create({
      name, email,
      password:    await bcrypt.hash(password, 10),
      backupCodes: backupCodesStored,
    });
    // ⚠️ Do NOT set auth cookie here
    // User must save backup codes first, then login manually
    res.status(201).json({
      message:     "Account created! Save your backup codes.",
      backupCodes: backupCodesRaw,     // shown once, never again
    });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    const input = String(req.body.email || req.body.username || "").trim().toLowerCase();
    if (!input || !password)
      return res.status(400).json({ message: "Please fill in all fields" });

    // Exact email match only (no $regex — prevents ReDoS + injection)
    const user = await User.findOne({
      $or: [{ email: input }, { name: input }],
    }).select("+loginAttempts +lockUntil");

    // ── Account lockout check ─────────────────────────────
    if (user && user.lockUntil && user.lockUntil > Date.now()) {
      const wait = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(423).json({
        message: `Account locked. Try again in ${wait} minute(s).`,
      });
    }

    const valid = user && await bcrypt.compare(password, user.password);

    if (!valid) {
      // Increment failed attempts
      if (user) {
        const attempts = (user.loginAttempts || 0) + 1;
        const update   = { loginAttempts: attempts };
        if (attempts >= 5) {
          update.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // lock 15 min
          console.warn(`[SECURITY] Account locked: ${user.email} after ${attempts} attempts`);
        }
        await User.findByIdAndUpdate(user._id, update);
      }
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // ── Success — reset lockout ───────────────────────────
    if (user.loginAttempts > 0 || user.lockUntil) {
      await User.findByIdAndUpdate(user._id, {
        $set: { loginAttempts: 0, lockUntil: null },
      });
    }

    console.log(`[AUTH] Login: ${user.email} from ${req.ip}`);
    const token = makeToken(user._id);
    setAuthCookie(res, token);
    res.json({ message: "Login successful", user: safeUser(user) });
  } catch (e) {
    console.error("[LOGIN ERR]", e.message);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

app.post("/api/auth/reset-password", authLimiter, async (req, res) => {
  try {
    const { newPassword, backupCode } = req.body;
    const email = normEmail(req.body.email);
    if (!email || !backupCode || !newPassword)
      return res.status(400).json({ message: "Email, backup code, and new password are required" });
    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email or backup code" });

    let matchedIndex = -1;
    const normalizedInput = backupCode.trim().toUpperCase();
    for (let i = 0; i < (user.backupCodes || []).length; i++) {
      const entry = user.backupCodes[i];
      if (!entry.used && await bcrypt.compare(normalizedInput, entry.hash)) {
        matchedIndex = i; break;
      }
    }
    if (matchedIndex === -1)
      return res.status(400).json({ message: "Invalid or already used backup code" });

    user.backupCodes[matchedIndex].used = true;
    user.password      = await bcrypt.hash(newPassword, 10);
    user.loginAttempts = 0;
    user.lockUntil     = null;
    await user.save();

    console.log(`[RESET] Password reset via backup code: ${email}`);
    res.json({ message: "Password reset successfully! You can now log in." });
  } catch (e) {
    console.error("[RESET ERR]", e.message);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

app.post("/api/auth/regenerate-backup-codes", guard, async (req, res) => {
  try {
    const { raw, stored } = await generateBackupCodes();
    await User.findByIdAndUpdate(req.uid, { backupCodes: stored });
    res.json({ message: "New backup codes generated!", backupCodes: raw });
  } catch (e) { res.status(500).json({ message: "Server error" }); }
});

app.post("/api/auth/logout", (req, res) => {
  const _p = process.env.NODE_ENV === "production";
  res.clearCookie("smm_token", { httpOnly:true, secure:_p, sameSite:_p?"none":"lax" });
  res.json({ message: "Logged out" });
});

app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const user = await User.findById(req.uid).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(safeUser(user));
  } catch (e) { res.status(500).json({ message: "Server error" }); }
});

app.post("/api/auth/change-password", guard, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: "Both fields are required" });
    if (newPassword.length < 6)
      return res.status(400).json({ message: "New password must be at least 6 characters" });
    const user = await User.findById(req.uid);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (!(await bcrypt.compare(currentPassword, user.password)))
      return res.status(401).json({ message: "Current password is incorrect" });
    await User.updateOne({ _id: req.uid }, { $set: { password: await bcrypt.hash(newPassword, 12) } });
    res.json({ message: "Password changed successfully" });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — PROVIDER (JAP passthrough)
══════════════════════════════════════════════════════════ */

/*
 * GET /api/provider/services
 * JAP returns an Array directly:
 * [{ service, name, type, category, rate, min, max, refill, cancel }, ...]
 * We normalize and cache 10 mins.
 */
/* ══════════════════════════════════════════════════════════
   BACKGROUND SYNC — JAP → MongoDB
   Runs every 1 hour. User never waits for JAP API.
══════════════════════════════════════════════════════════ */
let _syncRunning = false;

async function syncServicesFromJAP() {
  if (_syncRunning) { console.log("[SYNC] Already running, skipped"); return; }
  _syncRunning = true;
  const startAt = Date.now();
  console.log("[SYNC] Fetching services from provider...");

  try {
    const raw  = await japAPI({ action: "services" });
    const arr  = (Array.isArray(raw) ? raw : Object.values(raw)).map(s => ({
      service_id:   String(s.service || s.service_id || ""),
      name:         s.name         || "",
      type:         s.type         || "Default",
      category:     s.category     || "Other",
      rate:         String(s.rate  || "0"),
      min:          String(s.min   || "10"),
      max:          String(s.max   || "10000000"),
      refill:       !!s.refill,
      cancel:       !!s.cancel,
      average_time: s.average_time || s.avg_time || null,
    })).filter(s => s.service_id);

    // Bulk upsert into MongoDB (fast, atomic)
    const ops = arr.map(s => ({
      updateOne: {
        filter:  { service_id: s.service_id },
        update:  { $set: s },
        upsert:  true,
      },
    }));
    const result = await ServiceCache.bulkWrite(ops, { ordered: false });
    const elapsed = ((Date.now() - startAt) / 1000).toFixed(1);
    console.log(`[SYNC] ✅ ${arr.length} services synced to DB in ${elapsed}s (upserted: ${result.upsertedCount}, modified: ${result.modifiedCount})`);

  } catch (e) {
    console.error(`[SYNC] ❌ Fetch failed — keeping existing DB data: ${e.message}`);
    // No action — old DB data remains valid
  } finally {
    _syncRunning = false;
  }
}

/*
 * GET /api/provider/services — instant from MongoDB DB cache
 * Background sync keeps DB fresh every 1 hour
 */
app.get("/api/provider/services", async (req, res) => {
  try {
    const services = await ServiceCache.find({})
      .select("-__v -createdAt -updatedAt")
      .lean();

    if (services.length === 0) {
      // DB empty (first run) — trigger sync and tell frontend to retry
      console.log("[SERVICES] DB empty, triggering background sync...");
      syncServicesFromJAP();    // background, don't await
      return res.status(202).json({
        message: "Services ကို ပြင်ဆင်နေပါသည် — ခဏစောင့်ပြီး ပြန်ကြည့်ပါ (30s)",
        syncing: true,
        services: [],
      });
    }

    // Sort by numeric service_id
    services.sort((a, b) => parseInt(a.service_id) - parseInt(b.service_id));
    console.log(`[SERVICES] Served ${services.length} services from DB`);
    res.json(services);

  } catch (e) {
    console.error("[SERVICES ERR]", e.message);
    res.status(500).json({ message: "Services ဆွဲမရပါ — ထပ်ကြိုးစားပါ" });
  }
});


/*
 * GET /api/provider/balance
 * JAP: { balance: "100.84292", currency: "USD" }
 */
app.get("/api/provider/balance", guard, async (req, res) => {
  try { res.json(await japAPI({ action: "balance" })); }
  catch (e) { res.status(502).json({ message: e.message }); }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — ORDERS
══════════════════════════════════════════════════════════ */

/*
 * POST /api/orders
 * Body: { serviceId, serviceName, category, link, quantity, chargeMMK }
 * JAP Add response: { "order": 23501 }  ← use data.order (not data.orderID)
 */
app.post("/api/orders", guard, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const { serviceId, serviceName, category, link, quantity, chargeMMK, comments } = req.body;
    if (!serviceId || !link || !quantity || !chargeMMK)
      return res.status(400).json({ message: "serviceId, link, quantity, chargeMMK required" });

    const user = await User.findById(req.uid).session(session);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.balance < chargeMMK)
      return res.status(400).json({ message: `Insufficient balance. Need ${chargeMMK} Ks, have ${user.balance} Ks` });

    user.balance -= chargeMMK; user.balanceSpent += chargeMMK; user.totalOrders += 1;
    await user.save({ session });

    const [order] = await Order.create([{
      user: req.uid, serviceId, serviceName: serviceName || "",
      category: category || "", link, quantity,
      chargeMMK, chargeUSD: parseFloat((chargeMMK / MMK_RATE).toFixed(4)),
      status: "Processing",
    }], { session });

    // ── Call JAP API ──────────────────────────────────────
    let providerRes;
    try {
      // Build JAP add payload — include comments if present (Custom Comments type)
      const japPayload = {
        action:   "add",
        service:  serviceId,
        link:     link,
        quantity: quantity,
      };
      if (comments) japPayload.comments = comments;
      providerRes = await japAPI(japPayload);
    } catch (provErr) {
      // Refund on failure
      user.balance += chargeMMK; user.balanceSpent -= chargeMMK; user.totalOrders -= 1;
      await user.save({ session });
      order.status = "Failed"; order.providerError = provErr.message;
      await order.save({ session });
      await session.commitTransaction(); session.endSession();
      return res.status(502).json({ message: provErr.message });
    }

    // JAP returns { "order": 23501 } ← key is "order" not "orderID"
    order.providerOrderId = providerRes.order;
    order.status = "Pending";
    await order.save({ session });
    await session.commitTransaction(); session.endSession();

    console.log(`[ORDER] ${order._id} → JAP #${providerRes.order}`);
    res.status(201).json({
      message: "Order placed successfully",
      orderId: order._id,
      providerOrderId: providerRes.order,   // JAP: .order
      remainingBalance: user.balance,
      order: { id: order._id, serviceId, serviceName, link, quantity, chargeMMK, status: order.status, createdAt: order.createdAt },
    });
  } catch (e) {
    await session.abortTransaction(); session.endSession();
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* GET /api/orders — paginated list */
app.get("/api/orders", guard, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const filter = { user: req.uid };
    if (req.query.status) filter.status = req.query.status;
    const [orders, total] = await Promise.all([
      Order.find(filter).sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).lean(),
      Order.countDocuments(filter),
    ]);
    res.json({ orders, pagination: { page, limit, total, pages: Math.ceil(total/limit) } });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
});

/* GET /api/orders/:id */
app.get("/api/orders/:id", guard, async (req, res) => {
  try {
    if (!isMongoId(req.params.id))
      return res.status(400).json({ message: "Invalid order ID" });
    const order = await Order.findOne({ _id: req.params.id, user: req.uid }).lean();
    if (!order) return res.status(404).json({ message: "Order not found" });
    res.json(order);
  } catch (e) { res.status(500).json({ message: "Server error" }); }
});

/*
 * POST /api/orders/:id/sync-status
 * JAP status response: { status, start_count, remains, charge, currency }
 */
app.post("/api/orders/:id/sync-status", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId) return res.status(400).json({ message: "No provider order ID" });

    const data = await japAPI({ action: "status", order: order.providerOrderId });

    // JAP field mapping:
    order.status     = data.status      || order.status;     // JAP: status (not orderStatus)
    order.startCount = data.start_count || order.startCount; // JAP: start_count (not startCount)
    order.remains    = parseFloat(data.remains || 0);        // JAP: remains (not remaining_amount)
    // Note: JAP does not have refunded_amount field
    await order.save();

    res.json({ message: "Status synced", order, providerData: data });
  } catch (e) {
    console.error("[SYNC ERR]", e.message);
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/sync-bulk
 * JAP multiple status: action=status, orders=id1,id2,id3
 * Response: { "1": { status, start_count, remains, ... }, "10": { error: "..." }, ... }
 */
app.post("/api/orders/sync-bulk", guard, async (req, res) => {
  try {
    const { orderIds } = req.body;
    if (!Array.isArray(orderIds) || !orderIds.length)
      return res.status(400).json({ message: "orderIds array required" });
    if (orderIds.length > 100)
      return res.status(400).json({ message: "Max 100 orders per request" });

    const orders = await Order.find({ _id: { $in: orderIds }, user: req.uid });
    const pids   = orders.map(o => o.providerOrderId).filter(Boolean);
    if (!pids.length) return res.json({ message: "No provider IDs found", updated: 0 });

    // JAP: use "orders" (plural) for multiple status check
    const data = await japAPI({ action: "status", orders: pids.join(",") });

    let updated = 0;
    for (const o of orders) {
      const d = data[String(o.providerOrderId)];
      if (!d || d.error) continue;                    // skip errors
      o.status     = d.status      || o.status;
      o.startCount = d.start_count || o.startCount;
      o.remains    = parseFloat(d.remains || 0);
      await o.save(); updated++;
    }
    res.json({ message: `${updated} orders updated`, updated });
  } catch (e) { res.status(502).json({ message: e.message }); }
});

/*
 * POST /api/orders/:id/refill
 * JAP: action=refill, order=<id>
 * Response: { "refill": "1" }
 */
app.post("/api/orders/:id/refill", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId) return res.status(400).json({ message: "No provider order ID" });

    const data = await japAPI({ action: "refill", order: order.providerOrderId });
    // JAP response: { refill: "1" } → refill ID
    order.status = "Refill Requested";
    await order.save();
    res.json({ message: "Refill requested", refillId: data.refill, providerResponse: data });
  } catch (e) { res.status(502).json({ message: e.message }); }
});

/*
 * POST /api/orders/:id/sync-status   ← Refresh order status from JAP
 * ─────────────────────────────────────────────────────────
 * JAP status response:
 *   { charge, start_count, status, remains, currency }
 */
app.post("/api/orders/:id/sync-status", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order)               return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId) return res.status(400).json({ message: "No provider order ID — cannot sync" });

    console.log(`[SYNC] Order ${order._id} → JAP #${order.providerOrderId}`);
    const data = await japAPI({ action: "status", order: order.providerOrderId });

    // Map JAP fields → DB fields
    order.status     = data.status      || order.status;
    order.startCount = data.start_count || order.startCount;
    order.remains    = parseFloat(data.remains || 0);
    await order.save();

    console.log(`[SYNC] Updated: status=${order.status} remains=${order.remains}`);
    res.json({
      message: "Status synced from JAP",
      order,
      providerData: {
        status:      data.status,
        start_count: data.start_count,
        remains:     data.remains,
        charge:      data.charge,
        currency:    data.currency,
      },
    });
  } catch (e) {
    console.error("[SYNC ERR]", e.message);
    res.status(502).json({ message: "Sync failed: " + e.message });
  }
});

/*
 * POST /api/orders/:id/cancel
 * ─────────────────────────────────────────────────────────
 * Flow:
 *   1. Find order & validate ownership / status
 *   2. Sync latest status from JAP (get fresh remains)
 *   3. Call JAP cancel API
 *   4. Parse JAP response — cancel:1 = success, cancel.error = failure
 *   5. Only on success: update DB + calculate refund
 *
 * JAP cancel response (array):
 *   [{ order: 2, cancel: 1 }]          ← success
 *   [{ order: 9, cancel: {error:"..."}} ← failure
 */
app.post("/api/orders/:id/cancel", guard, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    // ── 1. Find & validate ───────────────────────────────
    const order = await Order.findOne({ _id: req.params.id, user: req.uid }).session(session);
    if (!order)
      return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId)
      return res.status(400).json({ message: "This order has no provider ID — cannot cancel" });
    if (["Completed", "Canceled", "Cancelled"].includes(order.status)) {
      await session.abortTransaction(); session.endSession();
      return res.status(400).json({ message: `Order is already ${order.status} — cannot cancel` });
    }

    // ── 2. Sync latest remains from JAP before canceling ──
    let freshRemains = order.remains;
    try {
      const syncData = await japAPI({ action: "status", order: order.providerOrderId });
      freshRemains   = parseFloat(syncData.remains || 0);
      order.remains  = freshRemains;
      order.status   = syncData.status || order.status;
      console.log(`[CANCEL] Pre-cancel sync: status=${syncData.status} remains=${freshRemains}`);
    } catch (syncErr) {
      console.warn("[CANCEL] Pre-cancel sync failed (continuing anyway):", syncErr.message);
    }

    // ── 3. Call JAP cancel API ───────────────────────────
    console.log(`[CANCEL] Calling JAP cancel for order #${order.providerOrderId}`);
    const japResponse = await japAPI({
      action: "cancel",
      orders: String(order.providerOrderId),   // JAP uses "orders" (plural) even for single
    });
    console.log("[CANCEL] JAP response:", JSON.stringify(japResponse));

    // ── 4. Parse JAP cancel response ────────────────────
    // JAP returns: [{ order: <id>, cancel: 1 }]  or  [{ order: <id>, cancel: { error: "..." } }]
    let cancelSuccess = false;
    let japErrMsg     = "";

    if (Array.isArray(japResponse)) {
      const entry = japResponse.find(r => String(r.order) === String(order.providerOrderId))
                 || japResponse[0];
      if (entry) {
        if (entry.cancel === 1 || entry.cancel === "1") {
          cancelSuccess = true;
        } else if (entry.cancel && typeof entry.cancel === "object" && entry.cancel.error) {
          japErrMsg = entry.cancel.error;
        } else if (entry.cancel) {
          cancelSuccess = true;   // numeric non-error value = success
        }
      }
    } else if (japResponse && typeof japResponse === "object") {
      // Some panels return a single object
      if (japResponse.cancel === 1 || japResponse.cancel === "1") cancelSuccess = true;
      else if (japResponse.error) japErrMsg = japResponse.error;
      else cancelSuccess = true;
    }

    // ── 5a. JAP refused cancel ───────────────────────────
    if (!cancelSuccess) {
      await session.abortTransaction(); session.endSession();
      console.warn(`[CANCEL] JAP refused: ${japErrMsg}`);
      return res.status(400).json({
        message: japErrMsg
          ? `ငြင်းပယ်မရပါ: ${japErrMsg.replace(/jap/gi,"").trim()}`
          : "Cancel မလုပ်နိုင်ပါ — Order လုပ်ဆောင်နေဆဲ ဖြစ်သည်",
      });
    }

    // ── 5b. Cancel succeeded — calculate refund ──────────
    /*
     * Refund formula:
     *   delivered  = quantity - remains
     *   Full refund   → remains >= quantity (nothing delivered)
     *   Partial refund → remains > 0 (partially delivered)
     *   No refund      → remains === 0 (fully delivered — rare at cancel)
     */
    const quantity   = order.quantity   || 1;
    const chargeMMK  = order.chargeMMK  || 0;
    let   refundMMK  = 0;
    let   refundType = "none";

    if (freshRemains >= quantity) {
      // Nothing delivered → full refund
      refundMMK  = chargeMMK;
      refundType = "full";
    } else if (freshRemains > 0) {
      // Partial delivery → proportional refund
      refundMMK  = Math.floor(chargeMMK * (freshRemains / quantity));
      refundType = "partial";
    }
    // remains === 0: nothing left to refund

    // Update order status
    order.status = "Canceled";
    await order.save({ session });

    // Credit refund to user balance (atomic)
    let newBalance = null;
    if (refundMMK > 0) {
      const updatedUser = await User.findByIdAndUpdate(
        req.uid,
        { $inc: { balance: refundMMK, balanceSpent: -refundMMK } },
        { new: true, session }
      );
      newBalance = updatedUser.balance;
      console.log(`[CANCEL] Refund ${refundType}: ${refundMMK} Ks → user ${req.uid}`);
    }

    await session.commitTransaction();
    session.endSession();

    res.json({
      message:   `Order canceled. ${refundMMK > 0 ? refundMMK.toLocaleString() + " Ks refunded to your balance." : "No refund (order was fully delivered)."}`,
      refundMMK,
      refundType,    // "full" | "partial" | "none"
      newBalance,
      order: { _id: order._id, status: order.status, remains: order.remains },
    });

  } catch (e) {
    await session.abortTransaction();
    session.endSession();
    console.error("[CANCEL ERR]", e.message);
    res.status(500).json({ message: "Cancel မအောင်မြင်ပါ — " + e.message.replace(/\[JAP\]\s*/gi, "").replace(/JAP/gi, "").trim() });
  }
});


/* ══════════════════════════════════════════════════════════
   ROUTES — FUND REQUESTS (User)
══════════════════════════════════════════════════════════ */

/* POST /api/funds/request  — user submits deposit */
app.post("/api/funds/request", guard, upload.single("screenshot"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ message: "Screenshot is required" });
    const { transactionId, amount } = req.body;
    if (!transactionId || transactionId.trim().length < 4)
      return res.status(400).json({ message: "Transaction ID is required (min 4 chars)" });

    const screenshotUrl = await uploadToImgBB(req.file.buffer);
    const user = await User.findById(req.uid);

    const fundReq = await FundRequest.create({
      userId:        req.uid,
      transactionId: transactionId.trim(),
      screenshotUrl,
      amount:        amount ? parseInt(amount) : 0,
      status:        "Pending",
    });

    console.log(`[FUND] Request ${fundReq._id} by ${user.email} txn:${transactionId}`);
    res.status(201).json({
      message:   "Fund request submitted! Admin will review and approve shortly.",
      requestId: fundReq._id,
    });
  } catch (e) {
    console.error("[FUND ERR]", e.message);
    res.status(500).json({ message: e.message });
  }
});

/* GET /api/funds/history  — user's own deposit history */
app.get("/api/funds/history", guard, async (req, res) => {
  try {
    const list = await FundRequest.find({ userId: req.uid })
      .sort({ createdAt: -1 }).limit(20);
    res.json(list);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — ADMIN
══════════════════════════════════════════════════════════ */

/* GET /api/admin/me  — verify admin token */
app.get("/api/admin/me", adminGuard, (req, res) => {
  res.json({ isAdmin: true, email: req.adminUser.email, name: req.adminUser.name });
});

/* GET /api/admin/fund-requests?status=Pending */
app.get("/api/admin/fund-requests", adminGuard, async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await FundRequest.find(filter)
      .populate("userId", "name email balance isAdmin")
      .sort({ createdAt: -1 });
    res.json(list);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* POST /api/admin/fund-requests/:id/approve */
app.post("/api/admin/fund-requests/:id/approve", adminGuard, async (req, res) => {
  try {
    const { amount, adminNotes } = req.body;
    const creditAmount = parseInt(amount);
    if (!creditAmount || creditAmount < 1)
      return res.status(400).json({ message: "amount (Ks) is required" });

    const fundReq = await FundRequest.findById(req.params.id).populate("userId");
    if (!fundReq)                    return res.status(404).json({ message: "Request not found" });
    if (fundReq.status !== "Pending")
      return res.status(400).json({ message: "Request already processed" });

    const updatedUser = await User.findByIdAndUpdate(
      fundReq.userId._id,
      { $inc: { balance: creditAmount } },
      { new: true }
    );

    fundReq.status     = "Approved";
    fundReq.amount     = creditAmount;
    fundReq.adminNotes = adminNotes || "";
    await fundReq.save();

    console.log(`[ADMIN] Approved ${creditAmount} Ks → ${fundReq.userId.email}`);
    res.json({
      message:    `Approved! ${creditAmount.toLocaleString()} Ks added to ${fundReq.userId.name}`,
      newBalance: updatedUser.balance,
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* POST /api/admin/fund-requests/:id/reject */
app.post("/api/admin/fund-requests/:id/reject", adminGuard, async (req, res) => {
  try {
    const fundReq = await FundRequest.findById(req.params.id);
    if (!fundReq)                    return res.status(404).json({ message: "Request not found" });
    if (fundReq.status !== "Pending")
      return res.status(400).json({ message: "Request already processed" });

    fundReq.status     = "Rejected";
    fundReq.adminNotes = req.body.adminNotes || "Rejected by admin";
    await fundReq.save();

    console.log(`[ADMIN] Rejected fund request ${fundReq._id}`);
    res.json({ message: "Request rejected" });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* GET /api/admin/users */
app.get("/api/admin/users", adminGuard, async (req, res) => {
  try {
    const users = await User.find({})
      .select("-password")
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* GET /api/admin/users/:id  — user detail + their fund requests */
app.get("/api/admin/users/:id", adminGuard, async (req, res) => {
  try {
    const user      = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    const fundReqs  = await FundRequest.find({ userId: req.params.id })
      .sort({ createdAt: -1 }).limit(20);
    const orders    = await Order.find({ user: req.params.id })
      .sort({ createdAt: -1 }).limit(20);
    res.json({ user, fundRequests: fundReqs, orders });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* PATCH /api/admin/users/:id/balance  — manual balance adjustment */
app.patch("/api/admin/users/:id/balance", adminGuard, async (req, res) => {
  try {
    const { balance } = req.body;
    if (typeof balance !== "number" || balance < 0)
      return res.status(400).json({ message: "Valid balance required" });
    const user = await User.findByIdAndUpdate(req.params.id, { balance }, { new: true });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "Balance updated", balance: user.balance });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* ══════════════════════════════════════════════════════════
   404 + Global Error Handler
══════════════════════════════════════════════════════════ */
app.use((_, res) => res.status(404).json({ message: "Route not found" }));

// Global error middleware — never expose stack traces to client
app.use((err, req, res, next) => {           // eslint-disable-line no-unused-vars
  const status = err.status || err.statusCode || 500;
  const isProd  = process.env.NODE_ENV === "production";

  console.error(`[ERROR] ${req.method} ${req.path} →`, err.message);

  res.status(status).json({
    message: isProd && status === 500
      ? "An internal error occurred. Please try again."
      : err.message || "Unexpected error",
  });
});

/* ══════════════════════════════════════════════════════════
   START
══════════════════════════════════════════════════════════ */
mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () => console.log(`🚀  Server on port ${PORT} | Provider: JAP`));

    // ── Background Sync Setup ──────────────────────────────
    // Check if DB has services already
    const count = await ServiceCache.countDocuments();
    if (count === 0) {
      console.log("[SYNC] First run — syncing services from provider...");
      syncServicesFromJAP();          // run immediately on first start
    } else {
      console.log(`[SYNC] DB has ${count} cached services — background sync scheduled`);
      // Sync once at startup to refresh, but don't block
      setTimeout(syncServicesFromJAP, 10000);   // 10s after startup
    }

    // Cron: sync every 1 hour (at minute 0 of every hour)
    cron.schedule("0 * * * *", () => {
      console.log("[CRON] Hourly sync triggered");
      syncServicesFromJAP();
    });
    console.log("[CRON] Hourly service sync scheduled ✅");
  })
  .catch(e => { console.error("❌  MongoDB:", e.message); process.exit(1); });
