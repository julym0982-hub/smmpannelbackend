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
const SECSERS_API_KEY = process.env.SECSERS_API_KEY || "";
const IMGBB_API_KEY = process.env.IMGBB_API_KEY || "";
const ADMIN_EMAILS  = (process.env.ADMIN_EMAILS || "")
  .split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
const SECSERS_API_URL = process.env.SECSERS_API_URL || "https://secsers.com/api/v2";
const MMK_RATE    = parseFloat(process.env.MMK_RATE || "4500");
const MARKUP         = parseFloat(process.env.MARKUP   || "1.2");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(u => u.trim()).filter(Boolean);

if (!MONGODB_URI) { console.error("❌  MONGODB_URI missing"); process.exit(1); }
if (!JWT_SECRET)  { console.error("❌  JWT_SECRET missing");  process.exit(1); }
if (!SECSERS_API_KEY) console.warn("⚠️  SECSERS_API_KEY not set");
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
      connectSrc: ["'self'", "https://secsers.com", "https://api.imgbb.com"],
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
async function providerAPI(params, _attempt = 0) {
  const MAX_ATTEMPTS = 4;          // 4 attempts total
  const TIMEOUTS     = [30000, 40000, 50000, 60000]; // grow per attempt
  const DELAYS       = [2000,  4000,  8000];          // backoff between retries

  const payload = new URLSearchParams();
  payload.append("key",    SECSERS_API_KEY);
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

  console.log(`[Provider] ${params.action.toUpperCase()} attempt ${_attempt + 1}/${MAX_ATTEMPTS}`);

  try {
    const { status, data } = await axios.post(
      SECSERS_API_URL,
      payload.toString(),
      {
        headers: {
          "Content-Type":     "application/x-www-form-urlencoded",
          "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept":           "application/json, text/javascript, */*; q=0.01",
          "Accept-Language":  "en-US,en;q=0.9",
          "Accept-Encoding":  "gzip, deflate, br",
          "Referer":          "https://secsers.com/",
          "Origin":           "https://secsers.com",
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
      console.warn(`[Provider] Attempt ${_attempt + 1} failed (${isTimeout ? "timeout" : err.response.status}). Retrying in ${delay / 1000}s...`);
      await new Promise(r => setTimeout(r, delay));
      return providerAPI(params, _attempt + 1);
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

/* ── FilterSettings — singleton doc ─────────────────────
   mode: "all" | "whitelist" | "blacklist"              */
const filterSettingsSchema = new mongoose.Schema({
  mode:            { type: String, enum: ["all","whitelist","blacklist"], default: "all" },
  customCategories:{ type: Map, of: String, default: {} },  // origName → customName
}, { timestamps: true });
const FilterSettings = mongoose.model("FilterSettings", filterSettingsSchema);

/* ── ServiceOverride — per-service customisation ────────*/
const serviceOverrideSchema = new mongoose.Schema({
  service_id:      { type: String, required: true, unique: true },
  custom_name:     { type: String, default: null },
  custom_category: { type: String, default: null },
  whitelisted:     { type: Boolean, default: false },
  blacklisted:     { type: Boolean, default: false },
  sort_order:      { type: Number, default: 999 },
}, { timestamps: true });
serviceOverrideSchema.index({ whitelisted: 1 });
serviceOverrideSchema.index({ blacklisted: 1 });
const ServiceOverride = mongoose.model("ServiceOverride", serviceOverrideSchema);

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
    const raw  = await providerAPI({ action: "services" });
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


/* ── JAP Service Cleanup ─────────────────────────────────
   Removes known JAP service IDs from ServiceCache DB.
   Runs once on startup if JAP services still exist.       */
const JAP_SERVICE_IDS = ["10237", "6920", "7447", "10019", "5951", "7973", "4250", "453", "3579", "7399", "8572", "8354", "6791", "6520", "6380", "5628", "6297", "9155", "2346", "10058", "9399", "1375", "4254", "1454", "3588", "10151", "9158", "367", "5768", "7835", "7903", "7870", "3034", "8238", "8791", "9573", "6840", "3905", "9536", "8736", "6672", "2357", "3365", "8819", "8208", "9497", "3029", "1708", "6091", "2457", "6498", "1605", "2722", "9301", "5774", "3482", "5781", "6286", "5826", "7884", "1460", "1973", "813", "9243", "2812", "6688", "9174", "7665", "3788", "8378", "8000", "7395", "7257", "2592", "1628", "8828", "8199", "2844", "9447", "3376", "9242", "7608", "128", "8376", "3023", "4332", "7531", "1156", "10062", "2170", "7126", "7879", "10212", "2872", "2488", "9492", "6073", "7692", "7916", "1150", "2880", "9519", "6074", "5562", "9367", "2704", "2350", "5036", "7708", "9467", "5563", "664", "4340", "7374", "9157", "10317", "6313", "3128", "5765", "7993", "1469", "2554", "3471", "2339", "8733", "2419", "7464", "6632", "1145", "1904", "3753", "8020", "10102", "8308", "2543", "7021", "6452", "2392", "4107", "7777", "6320", "3282", "7698", "1766", "9340", "1961", "666", "10314", "7968", "1198", "7188", "1960", "8319", "2657", "8578", "4299", "5831", "7337", "4372", "2398", "3597", "2709", "6459", "7102", "7959", "873", "6629", "7471", "2968", "2552", "793", "3252", "6367", "6134", "8549", "2710", "9442", "7837", "8495", "6864", "8003", "1161", "1824", "7772", "1064", "1330", "1858", "580", "8555", "7830", "173", "9144", "9199", "1894", "1823", "9055", "9152", "10132", "6886", "2496", "7853", "5567", "6142", "7689", "8085", "7735", "7622", "2381", "2763", "6087", "8302", "1637", "3851", "10021", "3434", "9421", "7114", "6370", "8098", "9469", "1570", "2658", "2813", "7119", "6229", "1981", "3902", "9974", "7646", "8741", "4133", "6211", "2614", "6963", "2852", "7750", "767", "2555", "5883", "10047", "4358", "6668", "1761", "6929", "164", "1810", "4121", "4172", "529", "1459", "2364", "1521", "10279", "4131", "8187", "2615", "3310", "9167", "2541", "3752", "8564", "5956", "10044", "6487", "10110", "7515", "8105", "7999", "8285", "285", "6316", "7582", "3429", "9566", "363", "6571", "7134", "9523", "5993", "6608", "8421", "9520", "2322", "2327", "9282", "3287", "395", "6946", "10156", "6558", "3504", "7836", "5715", "10145", "3893", "6630", "9291", "2480", "6875", "9356", "6917", "4219", "10201", "9170", "550", "8075", "665", "6899", "348", "3479", "7331", "2588", "324", "8062", "7687", "7267", "8797", "9281", "2687", "307", "2606", "8510", "6576", "2547", "7496", "8338", "10120", "2965", "6869", "8864", "7082", "9508", "6396", "7737", "7564", "7404", "1144", "10114", "6583", "5669", "1492", "7661", "4184", "6362", "2351", "6129", "1266", "6368", "443", "6162", "8804", "6591", "2601", "5949", "4244", "9494", "1435", "2108", "3843", "4431", "5754", "9294", "4265", "2460", "5877", "2750", "6721", "2655", "6510", "816", "8054", "7004", "7854", "2443", "8211", "7389", "8039", "1443", "6371", "244", "9504", "5932", "2557", "10282", "6868", "6664", "1441", "8026", "7693", "7839", "2593", "4325", "7963", "2994", "576", "7130", "9346", "6779", "2349", "6305", "4349", "4415", "5998", "4174", "1582", "6448", "9280", "6775", "7902", "10144", "906", "8106", "7156", "5692", "7888", "2422", "2806", "2766", "8446", "867", "2153", "3473", "7388", "6925", "1562", "8706", "7590", "6893", "2510", "214", "6940", "6008", "2876", "1613", "4361", "8231", "10189", "7901", "6657", "1513", "3892", "8459", "7797", "1993", "9574", "2997", "5770", "6580", "4995", "3867", "6226", "10196", "3318", "5701", "492", "9331", "8013", "6837", "9482", "2444", "2621", "8024", "8545", "4440", "3273", "10082", "5029", "8703", "6119", "7147", "1700", "2456", "9323", "8286", "9554", "8329", "9595", "1604", "3587", "5710", "9236", "4261", "8090", "3592", "1531", "10103", "2410", "6376", "8838", "1326", "7981", "5793", "9472", "126", "4279", "8440", "1598", "8707", "8080", "1985", "10119", "3258", "7766", "370", "2340", "847", "8009", "10087", "638", "3884", "5704", "1426", "8711", "10079", "6620", "7727", "1891", "2942", "4124", "6669", "7155", "3586", "5699", "933", "7143", "2361", "3536", "9422", "10173", "1471", "8470", "3750", "9563", "2152", "2686", "8202", "6835", "3841", "2830", "7118", "10112", "1601", "2705", "6859", "8946", "1346", "5992", "9513", "2723", "1282", "6509", "8526", "3872", "2664", "6907", "1828", "6560", "10245", "1683", "7327", "6406", "10147", "1664", "9404", "7167", "8600", "7864", "8038", "8977", "2078", "7454", "9286", "1506", "3844", "8101", "6262", "7553", "9502", "2850", "2628", "1866", "8565", "1965", "8198", "6673", "278", "5792", "1901", "5787", "7465", "2212", "6506", "7659", "8256", "1199", "2595", "2448", "7413", "3316", "615", "4328", "7474", "7527", "7412", "2853", "7892", "7339", "2565", "2775", "7008", "7655", "1323", "3028", "6393", "9238", "637", "8739", "1596", "3262", "7753", "9329", "2537", "10049", "6655", "8356", "6469", "3855", "6653", "7965", "2105", "8287", "8084", "3897", "4354", "5962", "2612", "1208", "2642", "8585", "1545", "7357", "6124", "2858", "7058", "4289", "1220", "3311", "3494", "9304", "2594", "2207", "865", "2449", "9017", "8705", "5829", "817", "2998", "9335", "1885", "7704", "2603", "2961", "9372", "3749", "5828", "9560", "10023", "2791", "2860", "6485", "7171", "7421", "9016", "4137", "7320", "9246", "5561", "8567", "113", "4245", "129", "4127", "6919", "1804", "6624", "9525", "2337", "2711", "7088", "7563", "3751", "8588", "6581", "6139", "2637", "448", "6726", "10195", "2949", "9457", "2487", "8579", "7991", "9334", "6665", "1860", "3092", "2783", "1572", "1549", "2483", "2640", "3280", "10223", "9556", "6719", "116", "8059", "7258", "1458", "2403", "9564", "5767", "9292", "2597", "6884", "2721", "6494", "7525", "9314", "1573", "364", "7683", "4398", "8696", "3496", "2693", "293", "403", "6594", "8055", "7613", "3854", "1504", "2635", "1210", "1174", "7261", "1196", "10184", "8793", "4148", "10169", "9160", "6723", "1986", "1021", "10280", "7081", "10265", "10115", "2644", "7295", "6006", "7321", "7566", "6125", "4220", "8709", "8662", "7348", "7099", "10306", "4375", "6796", "5903", "8717", "6975", "9461", "2530", "10248", "9412", "10215", "7550", "5718", "6652", "1200", "1555", "6685", "1565", "2701", "7834", "2996", "8372", "10174", "7405", "1642", "6018", "378", "9279", "1474", "7832", "8808", "7518", "804", "9125", "9164", "2718", "6488", "3834", "7997", "8405", "1962", "10225", "6692", "1907", "6017", "894", "5698", "6001", "4275", "7795", "490", "2959", "7514", "1560", "3495", "1577", "2182", "2544", "2848", "2714", "2991", "1811", "1996", "6872", "5694", "3345", "3277", "3009", "8781", "7083", "1368", "6369", "9487", "2782", "2590", "7857", "7908", "6251", "7816", "10025", "8314", "5970", "10004", "10312", "6489", "8388", "2652", "2681", "5797", "7600", "6531", "6300", "7746", "2803", "7648", "7377", "7998", "9181", "4242", "8025", "1914", "2479", "2815", "7333", "1896", "2913", "8807", "7966", "9363", "9151", "9512", "9056", "10238", "6663", "8469", "3424", "1903", "5898", "6934", "7615", "7620", "9979", "3360", "9594", "2625", "8810", "2702", "4163", "10285", "7656", "2834", "2773", "5627", "1434", "1445", "7824", "1237", "212", "6460", "4168", "6093", "2827", "9571", "5753", "4113", "9400", "1902", "9096", "6207", "7063", "5964", "5033", "2418", "8525", "9295", "10143", "7900", "9276", "1250", "2826", "7146", "9020", "9175", "7632", "9548", "1602", "1037", "6997", "2739", "1957", "3518", "1195", "1428", "9445", "4438", "960", "5980", "6145", "2631", "3130", "6912", "909", "5634", "6539", "6623", "578", "2797", "6903", "10289", "2373", "4336", "6777", "6615", "6901", "6395", "6989", "4360", "8701", "1753", "4371", "2708", "217", "4304", "341", "1271", "577", "7230", "2084", "7985", "8374", "9394", "9230", "819", "5963", "8035", "2620", "8778", "8752", "7260", "852", "4207", "1593", "1797", "8763", "8099", "8693", "3304", "10260", "8443", "5666", "3816", "7701", "8947", "7085", "10230", "2000", "2856", "2971", "8189", "3877", "8854", "8188", "10259", "9299", "2472", "2839", "7219", "2079", "1423", "8061", "8330", "7682", "6728", "1758", "8327", "4407", "2936", "10113", "6117", "3743", "2076", "1566", "9095", "2420", "6550", "2667", "112", "7690", "7752", "7200", "1796", "3754", "7194", "6379", "3864", "7722", "10125", "10318", "10117", "1415", "2387", "5791", "7186", "1329", "8652", "8715", "2818", "2604", "8574", "7154", "6502", "6317", "6374", "2164", "2393", "6144", "9429", "2294", "2531", "230", "4209", "8353", "7470", "2376", "9386", "8019", "7955", "2809", "360", "4239", "9522", "7354", "6331", "179", "7210", "10182", "2630", "8464", "7371", "8952", "1197", "7221", "9094", "10043", "2474", "3478", "9047", "3266", "3027", "1048", "6725", "2292", "1327", "6931", "1546", "2513", "2540", "8355", "2807", "8360", "4403", "3419", "1978", "2490", "4350", "3427", "1365", "8307", "8584", "4267", "1869", "7117", "5974", "9510", "4327", "8411", "7707", "2302", "2532", "2829", "169", "6795", "9541", "6508", "7638", "175", "4432", "6957", "3769", "3761", "2317", "2363", "7787", "2810", "1777", "6894", "6628", "2251", "1498", "9428", "7607", "7619", "2082", "2377", "2647", "8359", "1522", "2181", "5746", "8979", "1452", "2817", "2335", "9479", "8522", "8563", "5830", "7594", "4238", "9590", "8975", "6160", "361", "6845", "9018", "5979", "9178", "2832", "3382", "7341", "7583", "8834", "8439", "1592", "2462", "10208", "1168", "2160", "1864", "6518", "9298", "7644", "7407", "8816", "9326", "9317", "6943", "6256", "6009", "9490", "9341", "2367", "833", "7823", "3041", "7078", "8809", "9062", "10192", "7054", "8396", "7875", "6257", "2503", "1607", "3303", "493", "355", "8491", "6365", "2956", "1172", "8042", "8196", "7817", "4114", "7268", "1624", "4164", "6823", "5636", "912", "7820", "7723", "2958", "1843", "1425", "1619", "4394", "2304", "2793", "5705", "2734", "1977", "4337", "676", "2643", "1805", "6528", "8980", "7190", "3576", "3775", "2382", "1857", "2256", "8016", "2836", "2861", "10006", "9113", "10209", "5959", "3347", "4183", "7372", "6873", "9347", "6642", "6247", "2430", "7912", "127", "2869", "9474", "7724", "3802", "7187", "7890", "9316", "798", "5917", "8948", "7662", "4112", "7851", "618", "5924", "1169", "1511", "9097", "2409", "2659", "411", "2935", "2073", "8066", "2098", "8324", "8494", "4321", "1989", "8714", "6724", "8265", "8107", "9542", "10136", "10016", "3247", "2697", "2478", "4115", "1854", "3853", "2569", "1436", "3243", "9481", "2629", "7958", "6143", "10007", "6877", "8044", "6299", "8368", "3265", "4429", "8857", "4302", "4166", "1895", "8200", "2668", "8210", "6621", "4186", "9384", "2607", "6314", "2974", "9390", "8052", "2412", "9431", "8034", "1595", "7080", "2461", "1517", "8412", "6715", "2776", "6818", "1694", "5738", "1467", "10176", "6578", "2431", "6988", "5032", "10243", "1838", "8569", "6949", "10030", "7323", "2320", "2362", "6004", "3487", "7774", "6993", "4442", "2341", "6833", "7980", "7369", "2306", "2824", "7969", "6505", "6398", "1568", "1791", "7092", "6637", "6660", "1526", "7949", "5995", "7779", "6458", "8318", "6814", "3481", "3279", "5630", "8213", "3831", "7381", "1431", "3355", "7340", "6447", "7833", "2764", "7383", "6812", "6711", "8209", "3865", "6709", "1466", "2518", "10257", "8592", "9565", "3774", "7212", "7891", "10281", "526", "2577", "8663", "1193", "6902", "2347", "437", "8065", "10194", "1969", "1564", "2700", "2716", "5973", "1499", "1581", "9531", "9303", "8397", "4448", "10191", "2289", "8699", "2579", "2550", "2742", "4305", "998", "9506", "2436", "6114", "6625", "1418", "9569", "9473", "6562", "2464", "6525", "5923", "2636", "4333", "3025", "8558", "9116", "2093", "2617", "1096", "9373", "8333", "2698", "1794", "6330", "10116", "9495", "6516", "3524", "9458", "8276", "8949", "6691", "7452", "9103", "8193", "7463", "7726", "7896", "5864", "379", "6737", "10171", "10084", "8984", "8559", "8651", "1419", "9514", "8331", "10186", "6913", "6541", "2626", "2309", "5875", "8206", "10308", "9342", "10090", "9486", "10264", "359", "1422", "7387", "1500", "7605", "393", "1553", "3596", "6468", "6969", "2305", "9156", "6002", "9496", "9179", "2246", "2946", "5708", "8598", "6874", "6596", "855", "8216", "7956", "8639", "9418", "4425", "5985", "2572", "6694", "2731", "8966", "3499", "7733", "10127", "6720", "8045", "6897", "9119", "7952", "2423", "2493", "2683", "9361", "7113", "2300", "9388", "7202", "5027", "2514", "9232", "2432", "2822", "1075", "8586", "8855", "10142", "10290", "10061", "6453", "856", "5968", "8268", "6499", "10211", "1829", "1334", "7788", "7338", "7332", "3829", "779", "5939", "8445", "1507", "1852", "2952", "8232", "2313", "1558", "3873", "6640", "9278", "1279", "2720", "2740", "581", "6325", "7096", "2344", "1608", "2769", "6707", "3026", "3384", "775", "10088", "6935", "6734", "8863", "6005", "4170", "1007", "2427", "6994", "7528", "4111", "8043", "2135", "7367", "9425", "3771", "2260", "10161", "8611", "1251", "1813", "711", "7426", "9132", "9435", "5820", "9332", "795", "3583", "802", "2356", "2534", "1881", "7554", "8358", "2670", "7379", "2370", "6240", "3862", "7790", "6265", "8032", "3377", "6828", "7697", "7111", "3585", "2151", "4309", "5024", "1757", "357", "5989", "635", "8599", "7346", "5867", "2485", "5740", "1249", "6805", "2473", "7179", "8343", "4343", "7059", "9306", "6150", "1421", "866", "10055", "8404", "2730", "8263", "3374", "1518", "592", "3830", "964", "7595", "6579", "4342", "2745", "7124", "1163", "2330", "658", "3290", "6648", "7897", "3284", "5880", "2399", "2957", "996", "6882", "10296", "8858", "5643", "1292", "10020", "8590", "5695", "4108", "10221", "9997", "6689", "7954", "7871", "7409", "3758", "2650", "2748", "2608", "3275", "2149", "6788", "6710", "1050", "3852", "1030", "8410", "4410", "10309", "1016", "4412", "6952", "8306", "6020", "2446", "1778", "1722", "4443", "7636", "1898", "8762", "6595", "5709", "4397", "10133", "8957", "7224", "3357", "8978", "900", "1913", "1839", "5766", "9123", "9454", "5686", "2501", "2857", "171", "7894", "6493", "7497", "8273", "7115", "557", "5818", "2390", "6936", "2406", "6228", "5660", "2586", "8018", "2333", "2598", "8277", "3503", "8783", "7670", "8722", "5999", "2843", "7591", "791", "2575", "2868", "1490", "6717", "2523", "8391", "8518", "9110", "2682", "2146", "6538", "1479", "3261", "8612", "1276", "4433", "3486", "3438", "8788", "7994", "4176", "1213", "8719", "9375", "10297", "7160", "6495", "5795", "1396", "2753", "8447", "555", "2308", "6504", "7203", "2366", "1018", "7597", "6360", "7262", "7007", "5897", "5685", "9509", "2654", "4205", "7198", "5719", "6951", "8825", "2785", "2529", "9319", "2065", "5706", "10064", "8344", "6496", "2248", "6501", "6090", "9250", "2450", "2921", "1636", "1879", "2596", "2556", "6126", "7635", "2800", "4306", "854", "6241", "9378", "6456", "7002", "4246", "7765", "1859", "6575", "9290", "2805", "8934", "1136", "10303", "6722", "9360", "9021", "8813", "7128", "5560", "3838", "1218", "7396", "9244", "3765", "2771", "634", "7184", "3428", "8371", "8218", "2726", "1536", "10085", "6792", "4201", "6866", "7356", "10134", "8441", "6911", "1417", "2690", "9438", "218", "2563", "8613", "2835", "5822", "6450", "7623", "5028", "7633", "2245", "9462", "9248", "319", "10045", "8367", "8841", "1178", "2875", "2798", "7860", "9449", "4182", "8594", "6976", "2512", "8321", "4256", "1892", "7964", "6290", "8735", "5716", "8030", "9464", "2338", "2725", "8015", "8542", "1994", "5690", "2491", "5803", "3421", "4236", "3379", "8313", "8352", "8617", "7696", "5955", "1790", "10164", "3766", "6704", "10175", "10036", "1503", "6455", "7056", "6310", "2492", "8317", "4140", "6120", "10224", "6268", "1246", "6357", "1821", "1049", "6549", "3762", "6928", "9239", "208", "9977", "2173", "6916", "6138", "10066", "7599", "10026", "1841", "733", "9599", "9561", "6307", "2999", "9057", "6245", "8486", "9451", "9349", "9593", "4135", "8103", "9058", "6947", "3423", "3501", "5668", "10229", "6391", "7091", "8094", "677", "9443", "1211", "7378", "6693", "2332", "6816", "6986", "8413", "4257", "4255", "7887", "6979", "8419", "8609", "9289", "1494", "344", "2672", "3850", "2476", "2770", "6607", "2389", "6926", "9327", "6806", "414", "7373", "6817", "7762", "6600", "10277", "4444", "8862", "2519", "7403", "5997", "8309", "9491", "3784", "6896", "5870", "6128", "7144", "8341", "1151", "5633", "10028", "2676", "6923", "3008", "765", "6318", "9106", "6892", "2192", "1853", "8792", "8465", "10205", "803", "10250", "10054", "8298", "4317", "669", "8337", "1065", "10089", "1335", "2195", "9015", "9518", "2411", "9247", "3426", "6860", "8789", "8802", "2801", "3837", "7351", "2548", "3021", "7087", "8718", "6714", "9171", "8753", "7329", "6602", "6846", "6392", "2100", "10153", "9575", "8505", "2616", "8642", "2310", "8299", "6311", "9433", "6213", "4379", "6937", "8999", "7140", "2675", "2329", "2677", "1281", "2784", "8676", "3336", "4144", "8097", "3528", "8728", "7529", "10206", "729", "3886", "9138", "8704", "6918", "2291", "2404", "8012", "9237", "7747", "7166", "1192", "8695", "10086", "567", "8092", "2334", "530", "9312", "2993", "6454", "6865", "5703", "10138", "3367", "3335", "7266", "7614", "1817", "7741", "3251", "7125", "2990", "7883", "6556", "5895", "7189", "6995", "2678", "1982", "1095", "7427", "9559", "10104", "8304", "646", "3031", "7838", "8535", "1025", "8560", "9552", "9441", "9241", "2434", "4173", "3529", "8023", "8724", "2585", "10080", "6112", "10029", "1594", "2589", "9591", "7874", "7775", "9393", "3901", "7110", "7532", "8833", "5658", "7453", "6478", "3383", "10234", "901", "6702", "10170", "9980", "10295", "3351", "4413", "7271", "8316", "2581", "9288", "2930", "3299", "2133", "8048", "2639", "8315", "3745", "5946", "8357", "1291", "6512", "6813", "749", "2679", "9190", "5881", "4364", "7361", "1910", "2767", "6479", "3483", "1302", "5958", "6123", "7669", "2459", "6574", "7618", "9345", "8393", "8350", "9413", "8077", "2489", "7706", "6523", "2611", "3909", "9582", "4213", "5632", "1429", "9551", "2481", "6405", "6075", "6208", "3879", "8552", "5693", "6834", "939", "5641", "7899", "7005", "7400", "8078", "7507", "1446", "8820", "1272", "10304", "10319", "7895", "3246", "4181", "10032", "1992", "1950", "3807", "9240", "663", "8746", "6491", "5931", "5717", "8700", "10185", "2587", "3286", "9604", "8805", "7152", "454", "9153", "7084", "8561", "801", "10284", "7660", "2738", "1579", "9380", "2894", "8801", "9981", "9452", "7074", "8093", "404", "6966", "9448", "413", "8369", "2691", "6826", "6895", "8468", "5982", "7530", "6891", "8765", "6622", "6881", "3858", "10255", "7626", "9480", "2819", "2638", "1529", "742", "2752", "8821", "2733", "5873", "8497", "8548", "4318", "2981", "2920", "6141", "6627", "9450", "7116", "4253", "9307", "2354", "2507", "9343", "6296", "9297", "7611", "8512", "7139", "2433", "5908", "8336", "8553", "1097", "10033", "5031", "1645", "5950", "1067", "9468", "8201", "394", "8806", "3874", "9489", "794", "2755", "8473", "2619", "3791", "6553", "1639", "8541", "125", "2706", "6922", "8796", "4297", "9122", "9126", "1543", "5865", "8812", "6153", "6598", "8539", "6266", "5983", "9369", "850", "5823", "9975", "8641", "7769", "1882", "2315", "3298", "9544", "6644", "2253", "6584", "8524", "2729", "1868", "3476", "616", "1641", "224", "8194", "1451", "1488", "6970", "7886", "8513", "2536", "7416", "2331", "8817", "3580", "2789", "9315", "2567", "2673", "7408", "6394", "7672", "3292", "8740", "3883", "2396", "2774", "2408", "1640", "1486", "3244", "8664", "6526", "7705", "4330", "2452", "8669", "2516", "5672", "7386", "2624", "2651", "6639", "1711", "1603", "1533", "9268", "1990", "3493", "2932", "5933", "4326", "7131", "6960", "7089", "6915", "2369", "5916", "2671", "1988", "6932", "9546", "6807", "9350", "9336", "8033", "9976", "9603", "10042", "2314", "2759", "7097", "2862", "6612", "2407", "7183", "10083", "6551", "6534", "8471", "5702", "7466", "2746", "1799", "6264", "459", "8956", "4110", "4994", "8852", "7108", "9597", "7592", "7384", "2728", "2375", "9430", "6306", "2995", "1764", "7326", "2988", "2343", "2566", "2609", "9545", "3744", "1920", "1438", "1299", "6267", "9407", "4217", "9526", "6830", "6390", "6358", "3593", "6659", "2060", "9045", "7651", "3456", "7700", "8389", "8091", "6626", "1376", "8417", "4366", "7629", "732", "1721", "5802", "9500", "2397", "9498", "7159", "8777", "6708", "9501", "2820", "1776", "6221", "2498", "1806", "1154", "3594", "2724", "3895", "831", "7397", "3896", "800", "7951", "266", "7738", "10181", "8534", "1550", "5670", "9397", "1717", "6646", "7742", "1336", "1883", "3030", "7695", "9414", "6013", "8264", "6014", "1563", "6011", "8325", "1974", "9586", "7593", "5671", "8557", "5679", "442", "8766", "7335", "7181", "2440", "10262", "10038", "7473", "5878", "1473", "7410", "7516", "661", "8303", "6103", "6156", "392", "7106", "6696", "8499", "7006", "6890", "3497", "7736", "2551", "10227", "2395", "6984", "7393", "7653", "10242", "7990", "7972", "587", "9305", "1303", "7180", "4142", "2405", "1875", "2699", "5899", "7967", "6021", "2831", "10266", "2324", "1727", "2842", "10313", "6991", "6092", "6945", "9161", "2879", "1612", "969", "2312", "10180", "8037", "10014", "7222", "9376", "9389", "10111", "3581", "4368", "9596", "1447", "7169", "2526", "8666", "977", "7391", "7508", "9478", "9398", "8650", "822", "5752", "8102", "848", "9344", "6633", "5947", "6990", "444", "2881", "6094", "7462", "5801", "7204", "9598", "748", "9406", "441", "8708", "8665", "2584", "2841", "10177", "10097", "3819", "1475", "10135", "8186", "3484", "7001", "2467", "1557", "7673", "7610", "5981", "8095", "7915", "354", "7702", "2847", "1873", "1152", "2846", "5866", "4167", "1773", "744", "2561", "6697", "10095", "10035", "8240", "3876", "4216", "2814", "10050", "1297", "2437", "7161", "6618", "10122", "2428", "9117", "3237", "7652", "1191", "428", "1880", "6007", "7663", "4123", "6900", "2290", "4335", "8970", "10178", "4132", "6470", "8380", "2068", "3358", "6003", "8197", "7792", "6536", "4153", "9130", "1954", "2828", "10267", "7852", "746", "9150", "3827", "9287", "745", "10247", "7813", "6610", "9402", "8859", "4365", "3848", "1278", "1527", "9061", "1849", "6999", "10240", "2627", "10005", "10063", "8976", "1273", "4251", "1822", "8659", "9624", "6827", "6312", "2821", "1802", "8712", "5879", "8716", "380", "7390", "7401", "7587", "2102", "2070", "6249", "5689", "751", "6109", "7498", "4139", "2378", "1847", "6210", "8697", "3474", "2174", "1968", "2694", "2299", "9370", "4165", "9368", "1148", "8205", "4351", "2578", "8348", "3591", "5737", "2758", "2732", "8702", "8392", "6212", "1554", "8301", "2851", "1984", "1166", "3847", "1477", "6954", "7826", "5642", "8667", "8562", "7220", "7625", "6944", "5948", "4416", "7142", "1814", "7843", "8780", "6137", "8971", "7780", "4146", "7674", "7330", "7455", "2259", "10052", "9169", "2546", "1524", "4414", "8835", "8794", "853", "3350", "9139", "2261", "2194", "6529", "1736", "7211", "7075", "161", "6484", "3364", "6983", "1718", "2388", "6486", "1146", "2602", "3500", "2866", "9283", "2494", "7265", "2715", "166", "948", "1160", "1495", "4210", "6573", "8973", "1342", "8544", "1432", "6107", "1204", "10157", "6718", "9381", "1320", "2154", "905", "9476", "1855", "7793", "4234", "774", "8503", "1003", "6666", "7513", "6955", "1098", "8723", "2311", "2374", "2560", "633", "10046", "9140", "9517", "3773", "9270", "1819", "524", "8192", "7016", "6577", "1501", "10239", "1544", "5978", "3885", "9471", "9505", "5712", "7380", "1450", "1468", "4322", "7873", "5957", "9133", "10137", "8461", "9553", "6214", "2948", "5991", "2522", "1906", "8379", "3289", "3305", "3372", "7079", "7107", "3378", "7552", "2727", "6731", "1416", "2533", "1319", "6497", "10159", "8546", "1374", "3370", "8229", "9419", "7846", "6974", "6716", "6289", "9046", "6985", "8721", "2982", "2570", "10126", "781", "8573", "2695", "8366", "3747", "2865", "8823", "10298", "8784", "8795", "1510", "2119", "7694", "9521", "877", "2184", "8751", "10078", "8385", "7539", "8050", "9475", "1456", "4175", "6301", "7603", "2605", "10130", "2941", "6706", "2863", "9483", "7090", "6101", "8530", "6871", "8566", "1784", "9300", "2870", "6797", "864", "6661", "6563", "10048", "1280", "7197", "805", "8543", "7685", "3249", "1787", "6284", "8951", "2937", "3296", "10140", "6514", "10198", "3833", "9129", "2645", "5824", "8100", "8603", "7475", "8334", "1461", "2524", "4409", "232", "6953", "9079", "7621", "6384", "9511", "3839", "7878", "6832", "1893", "2159", "7957", "9173", "1772", "4445", "8786", "6862", "1769", "219", "8484", "1463", "1331", "2737", "6071", "9507", "7236", "7185", "6965", "10228", "5904", "10141", "2665", "9118", "7703", "5696", "8222", "9395", "6870", "1487", "7913", "10263", "6561", "1771", "5794", "3295", "7145", "8407", "2525", "6667", "9142", "2989", "4116", "1752", "8764", "1437", "6321", "2429", "7382", "8415", "9437", "3859", "7596", "4396", "9364", "3870", "7699", "2849", "8521", "9358", "7448", "6131", "7328", "2527", "7536", "3254", "2067", "2482", "3356", "10316", "7907", "1552", "1782", "7191", "1792", "2463", "3894", "1867", "1420", "1290", "8011", "6216", "6876", "8300", "6524", "5749", "4320", "8225", "9605", "3278", "7880", "3825", "2660", "5799", "2508", "2622", "7782", "6324", "3598", "3811", "2796", "2680", "1032", "5755", "570", "6799", "10100", "7789", "7847", "7691", "8384", "10076", "7858", "9111", "2502", "8656", "9026", "7576", "5631", "1509", "2391", "1190", "2075", "2877", "7643", "8230", "7349", "3253", "3498", "2158", "8725", "8967", "358", "9234", "6643", "439", "10222", "2193", "6904", "8064", "3521", "7394", "5687", "7370", "7469", "1561", "6016", "6836", "8607", "4136", "3317", "2326", "7948", "5987", "740", "2838", "6662", "8010", "4298", "764", "2185", "7182", "4352", "7961", "7825", "2208", "2799", "7647", "6552", "260", "6958", "9149", "2966", "2447", "9310", "2656", "6820", "8233", "10146", "479", "6540", "7094", "3828", "2517", "2854", "6513", "6888", "6244", "8782", "7616", "2318", "2685", "8340", "5711", "7882", "7205", "5739", "2062", "6243", "7920", "1484", "6010", "799", "7385", "1922", "9382", "7814", "1767", "982", "8850", "10160", "6680", "10139", "7264", "215", "9455", "8036", "7987", "6372", "1827", "1442", "6309", "3274", "6656", "10190", "9060", "8853", "10094", "9583", "6472", "9104", "399", "1345", "9308", "10244", "2402", "9101", "6819", "9159", "9100", "8204", "7322", "2165", "10187", "6530", "7863", "7208", "5626", "9338", "9499", "8596", "2371", "583", "1019", "283", "8261", "8981", "8390", "2072", "362", "8375", "6449", "950", "2760", "3849", "3005", "7630", "4243", "3272", "2328", "7325", "7360", "8219", "10254", "1657", "5984", "10251", "1074", "9362", "2486", "4145", "3826", "2210", "2255", "1889", "6631", "1165", "10129", "2804", "2454", "2127", "7456", "1017", "2973", "7368", "5771", "8081", "10203", "9184", "4247", "7334", "1845", "9309", "4300", "5745", "1737", "8047", "2342", "6698", "1231", "4162", "6366", "2368", "1556", "2528", "7819", "3759", "4303", "3526", "10193", "9320", "3248", "7650", "2455", "6304", "2435", "9293", "9112", "7885", "987", "8529", "4249", "2316", "8195", "6519", "2183", "10015", "584", "6927", "1465", "2892", "7178", "7038", "7129", "6227", "352", "2648", "1575", "6908", "8509", "7364", "7628", "7872", "2840", "3757", "10278", "10294", "7003", "1627", "449", "6527", "10202", "984", "2576", "9128", "7831", "2110", "4450", "7209", "1453", "2355", "9105", "2811", "4411", "5930", "2453", "406", "5825", "8217", "5662", "6326", "7355", "10183", "7207", "4446", "5977", "1304", "8861", "1448", "7732", "9337", "1147", "7538", "1298", "8339", "6500", "5640", "1644", "10197", "6619", "1812", "5994", "6209", "1216", "8836", "10241", "8523", "3502", "9124", "10219", "8547", "2509", "6135", "2825", "2777", "9107", "7606", "8710", "2148", "5868", "440", "7206", "6323", "3368", "6490", "6532", "4331", "6878", "7020", "9109", "8420", "5827", "10039", "5566", "6887", "8826", "5667", "7739", "9311", "6700", "8618", "6690", "7686", "6248", "2712", "2970", "1840", "2790", "4278", "9357", "7773", "7764", "741", "8320", "8104", "2780", "3259", "6815", "8373", "9420", "7174", "3898", "8079", "176", "7468", "8827", "6603", "9446", "8386", "10216", "7345", "2553", "7376", "4435", "1616", "10200", "636", "6651", "3812", "3381", "6557", "10305", "4417", "1515", "1377", "10302", "9366", "6359", "1625", "10031", "731", "7415", "2180", "6517", "7842", "1567", "6967", "7168", "7654", "8472", "4353", "9549", "1444", "9417", "4130", "8830", "4232", "7093", "851", "2558", "2196", "7537", "3835", "1262", "6163", "5731", "3361", "8310", "7158", "2663", "7850", "2859", "6824", "797", "3227", "3306", "10051", "7725", "6650", "2646", "4404", "7375", "455", "3485", "6942", "6102", "2303", "7109", "2833", "10093", "10024", "9488", "3840", "2761", "1547", "6270", "7017", "6645", "1325", "7791", "1998", "10246", "6914", "8829", "1861", "7269", "3260", "1863", "2415", "6831", "2895", "6978", "7986", "2634", "7428", "5730", "4258", "1480", "4324", "10166", "4235", "6217", "7989", "6905", "8251", "4381", "2794", "1548", "325", "4272", "6941", "9120", "3226", "1768", "178", "3776", "4401", "6157", "9196", "8653", "7763", "2549", "7796", "429", "6215", "8803", "3767", "3472", "3022", "434", "4430", "5747", "2247", "1809", "3510", "9355", "1157", "6883", "6258", "3250", "2325", "2583", "10121", "3875", "9503", "2500", "4268", "8831", "6982", "10168", "9198", "2438", "2469", "292", "4405", "2743", "1497", "2441", "5960", "9550", "7366", "4109", "3878", "4273", "9584", "1209", "5936", "3880", "2497", "10293", "1219", "566", "7445", "911", "6242", "7524", "9185", "2504", "8271", "7984", "5038", "519", "7270", "6022", "6921", "295", "6593", "9532", "5789", "2475", "6829", "8818", "9405", "2401", "7822", "10235", "3343", "8409", "3861", "743", "368", "2539", "8442", "6503", "5734", "9477", "750", "2319", "1569", "2792", "6601", "7828", "10152", "6462", "7778", "102", "553", "2458", "6483", "9466", "10301", "8950", "8051", "792", "1788", "10233", "2521", "8082", "747", "5026", "10131", "5732", "9099", "8345", "6992", "9348", "10022", "3283", "4185", "6825", "6987", "2203", "3866", "2580", "8370", "1878", "6597", "4319", "4420", "2600", "6328", "2353", "9374", "9078", "7962", "3263", "1274", "6533", "6303", "5876", "8349", "3910", "9177", "2477", "7223", "8720", "2323", "2413", "6272", "8832", "3824", "5726", "1621", "2206", "6670", "8974", "9354", "9059", "10059", "7402", "7153", "1155", "2864", "1277", "225", "9973", "4169", "1808", "10099", "6457", "7344", "9013", "1333", "9054", "4141", "4359", "2762", "776", "7617", "3359", "8589", "8416", "7053", "9459", "2163", "6116", "8017", "6924", "617", "5697", "170", "2213", "4437", "9352", "6147", "8074", "6910", "6959", "438", "5688", "7214", "3375", "9460", "2359", "2426", "10231", "9484", "2416", "1483", "6471", "8698", "9485", "1439", "10258", "8014", "1203", "9330", "2633", "1259", "401", "3818", "2003", "4240", "8538", "402", "2495", "8220", "4274", "2765", "8520", "10092", "9172", "7517", "1535", "2641", "6274", "2484", "1697", "2747", "3024", "6492", "8096", "3300", "2307", "4367", "4276", "7424", "10226", "2649", "2618", "3792", "8207", "6977", "9558", "9602", "6730", "8869", "4128", "6614", "8322", "7604", "1916", "9284", "1004", "2802", "2470", "8506", "5039", "639", "7467", "554", "2662", "668", "6699", "8606", "9524", "949", "8798", "2573", "10253", "9572", "3420", "6609", "10027", "2808", "9313", "6511", "2505", "8326", "1876", "10179", "1520", "3525", "7499", "7259", "4329", "6111", "9528", "9998", "1830", "10261", "1489", "4436", "2439", "8851", "7127", "9302", "369", "2910", "8485", "10091", "579", "8657", "2703", "715", "6679", "8239", "2917", "8969", "1171", "883", "8221", "10065", "6972", "7132", "3888", "1378", "7586", "7342", "9165", "2845", "8028", "10118", "9296", "7392", "2445", "6809", "8507", "10188", "2386", "2365", "3242", "9408", "6889", "7324", "10096", "2095", "2009", "8454", "1530", "9371", "5800", "7423", "10311", "2816", "9600", "7898", "9127", "2795", "10315", "6361", "471", "9182", "1597", "6867", "2442", "6973", "4424", "8576", "2696", "6713", "4143", "8323", "7195", "7624", "2425", "2417", "4218", "424", "6962", "2468", "1440", "5821", "6161", "6613", "8587", "8502", "2358", "2542", "6677", "8972", "8458", "1836", "7905", "6507", "2855", "6636", "2653", "3349", "6879", "6397", "2744", "6322", "9080", "9416", "3748", "8457", "2983", "7598", "3238", "7889", "4373", "9516", "6705", "9321", "2535", "4204", "8049", "575", "8060", "6108", "3584", "9470", "2874", "1525", "7740", "4439", "3836", "5629", "9396", "1732", "5922", "7876", "2967", "2321", "1523", "8815", "6000", "6159", "2147", "9403", "3863", "6572", "1478", "1884", "9141", "6712", "3887", "2385", "8654", "1031", "2969", "6658", "7460", "7919", "7565", "3764", "1464", "3362", "7950", "4399", "2511", "2150", "7906", "7406", "6015", "10034", "7631", "312", "8234", "6738", "9777", "2751", "7904", "1508", "2591", "6475", "9453", "3019", "1842", "7634", "7589", "9456", "6259", "7911", "6158", "7000", "2873", "2754", "9351", "8029", "4203", "6473", "2719", "8237", "8953", "2383", "1626", "6218", "6961", "8508", "7671", "1923", "3285", "8041", "3746", "9359", "4125", "8860", "1826", "8730", "7218", "1214", "3435", "2610", "2823", "523", "1301", "1654", "8492", "9562", "6140", "8053", "6939", "6113", "4248", "2953", "7353", "4428", "4307", "1398", "659", "3832", "10162", "1476", "7783", "7444", "6476", "4341", "2871", "7841", "7086", "2336", "8057", "3422", "6635", "5798", "10053", "10287", "7105", "7829", "4434", "2582", "10149", "2684", "4122", "8540", "6616", "1028", "8346", "10081", "7845", "9547", "546", "7754", "8215", "5788", "7472", "2520", "6599", "9168", "9115", "3869", "7411", "8262", "3756", "9555", "8305", "667", "6638", "6617", "9019", "1634", "1430", "981", "8799", "7960", "1264", "2867", "8517", "5673", "1905", "2421", "2781", "3302", "7849", "10098", "6933", "9982", "8713", "2400", "9231", "632", "9093", "6703", "3090", "9011", "7256", "8347", "1153", "9108", "1801", "8800", "1449", "6736", "6522", "2717", "809", "895", "6019", "7609", "8814", "9585", "2987", "8027", "2837", "2384", "3742", "10101", "9436", "6930", "2465", "2471", "3264", "7584", "9543", "3881", "2749", "9365", "1502", "2736", "10124", "1606", "167", "2707", "9423", "4126", "2623", "3520", "3245", "2931", "8870", "5034", "1457", "5874", "5996", "1856", "8190", "1724", "7076", "5775", "8619", "3772", "6381", "1427", "7627", "8312", "8328", "10307", "1455", "1300", "5037", "2692", "818", "7684", "7818", "9465", "2786", "2741", "6382", "8655", "1995", "3523", "9052", "3380", "2050", "10288", "9537", "2778", "6641", "3425", "6980", "662", "2912", "6554", "1332", "6684", "1248", "2599", "5035", "9515", "7953", "3530", "5961", "7540", "8608", "10077", "8577", "8063", "6671", "2301", "8519", "9195", "6695", "5707", "4374", "5969", "1283", "2360", "2713", "8729", "3256", "7542", "6477", "2538", "6880", "7585", "6133", "7359", "2094", "8496", "2564", "2380", "5952", "2211", "7688", "8083", "2779", "1726", "556", "8734", "3369", "10165", "6590", "7844", "8056", "7982", "8761", "525", "9200", "9249", "2506", "7170", "1600", "698", "1733", "8837", "7893", "7992", "2632", "2466", "2757", "6681", "7057", "8266", "1202", "5665", "6146", "7910", "2674", "5896", "2688", "3257", "8058", "9134", "7526", "3091", "9044", "7640", "1754", "1972", "6451", "3868", "6535", "10300", "8670", "2571", "2735", "1424", "2161", "4206", "5748", "8243", "2669", "6649", "2939", "8212", "1206", "2756", "513", "3129", "6981", "1622", "7347", "7336", "10210", "7757", "8267", "2012", "9274", "3899", "6968", "4134", "6611", "6269", "7768", "7657", "5733", "5691", "6246", "9570", "5639", "8640", "3301", "2568", "2878", "4334", "9984", "6998", "1825", "8071", "5882", "7840", "300", "9014", "8278", "3595", "7141", "2214", "2414", "6582", "10207", "4147", "1068", "1947", "8214", "10002", "3582", "8422", "1967", "7971", "2562", "220", "1215", "7263", "3763", "3477", "4241", "9440", "6375", "8279", "254", "2120", "7612", "6263", "1370", "2559", "1275", "7658", "2545", "1987", "4138", "3288", "7675", "2661", "2772", "983", "7815", "5986", "954", "4208", "685", "6956", "2787", "4441", "6383", "2209", "6822", "8593", "9333", "849", "340", "6118", "6909", "7867", "5988", "8460", "1759", "2352", "1735", "9154", "6938", "2257", "2499", "5769", "3320", "1101", "8031", "1844", "6885", "9592", "7072", "9379", "10286", "3889", "6373", "7914", "2394", "1559", "1576", "7196", "7865", "1149", "8811", "1638", "9328", "8856", "6130", "5030", "9978", "1571", "6701", "6132", "778", "1414", "1207", "7983", "6250", "2788", "2768", "8839", "4323", "1789", "8401", "9183", "719", "2204", "10204", "8394", "8504", "7848", "7821", "9197", "9131", "6996", "8342", "2574", "1514", "6950", "2372", "2613", "7866", "1482", "9114", "7756", "9983", "1795", "1022", "6634", "6898", "1630", "6302", "9444", "6273", "7909", "1194", "2689", "8614", "9385", "8021", "9121", "7199", "10283", "1862", "1472", "2515", "8311", "2451", "9493", "8658", "2293", "5700", "9387", "3315", "4180", "6906", "6971", "6012", "545", "8022", "6735", "1047", "9401", "6964", "7827", "7446", "9415", "8351", "3297", "9463", "5714", "6821", "7577", "2666", "9339", "10199", "2379", "8297", "9166", "1433", "9235", "8335", "3860", "6647", "6948", "9557", "10220", "521", "720", "3385", "5796", "9601", "10249", "10060", "9012", "773", "3871"];

async function removeJAPServices() {
  try {
    const result = await ServiceCache.deleteMany({
      service_id: { $in: JAP_SERVICE_IDS.map(String) }
    });
    if (result.deletedCount > 0)
      console.log(`[CLEANUP] Removed ${result.deletedCount} JAP services from DB`);
    else
      console.log("[CLEANUP] No JAP services found in DB ✅");
  } catch(e) {
    console.error("[CLEANUP ERR]", e.message);
  }
}

/*
 * GET /api/provider/services — instant from MongoDB DB cache
 * Background sync keeps DB fresh every 1 hour
 */
app.get("/api/provider/services", async (req, res) => {
  try {
    const [services, overrides, settingsDoc] = await Promise.all([
      ServiceCache.find({}).select("-__v -createdAt -updatedAt").lean(),
      ServiceOverride.find({}).lean(),
      FilterSettings.findOne().lean(),
    ]);

    if (services.length === 0) {
      console.log("[SERVICES] DB empty — triggering background sync...");
      syncServicesFromJAP();
      return res.status(202).json({
        message: "Services ကို ပြင်ဆင်နေပါသည် — ခဏစောင့်ပြီး ပြန်ကြည့်ပါ (30s)",
        syncing: true, services: [],
      });
    }

    const mode       = settingsDoc?.mode || "all";
    const catMap     = settingsDoc?.customCategories
      ? Object.fromEntries(settingsDoc.customCategories) : {};
    const overrideMap = {};
    overrides.forEach(o => { overrideMap[String(o.service_id)] = o; });

    // Apply name / category overrides to every service
    // Also auto-remove any JAP-exclusive services (category or name contains "JAP")
    const JAP_PATTERNS = /\bjap\b|jap exclusive|justanotherpanel/i;

    const JAP_IDS_SET = new Set(JAP_SERVICE_IDS.map(String));
    let result = services
      .filter(s => {
        // Remove by known JAP service ID
        if (JAP_IDS_SET.has(String(s.service_id))) return false;
        // Remove by JAP-exclusive category/name
        const cat  = (s.category || '').toLowerCase();
        const name = (s.name     || '').toLowerCase();
        if (JAP_PATTERNS.test(cat) || JAP_PATTERNS.test(name)) return false;
        return true;
      })
      .map(s => {
        const o = overrideMap[String(s.service_id)];
        return {
          ...s,
          name:     (o?.custom_name     || s.name),
          category: (o?.custom_category || catMap[s.category] || s.category),
        };
      });

    // Filter by mode
    if (mode === "whitelist") {
      result = result.filter(s => overrideMap[String(s.service_id)]?.whitelisted);
      result.sort((a, b) =>
        (overrideMap[a.service_id]?.sort_order || 999) -
        (overrideMap[b.service_id]?.sort_order || 999));
    } else if (mode === "blacklist") {
      result = result.filter(s => !overrideMap[String(s.service_id)]?.blacklisted);
      result.sort((a, b) => parseInt(a.service_id) - parseInt(b.service_id));
    } else {
      result.sort((a, b) => parseInt(a.service_id) - parseInt(b.service_id));
    }

    console.log(`[SERVICES] ${result.length} services served (mode: ${mode})`);
    res.json(result);

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
  try { res.json(await providerAPI({ action: "balance" })); }
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
      const providerPayload = {
        action:   "add",
        service:  serviceId,
        link:     link,
        quantity: quantity,
      };
      if (comments) providerPayload.comments = comments;
      providerRes = await providerAPI(providerPayload);
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

    const data = await providerAPI({ action: "status", order: order.providerOrderId });

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
    const data = await providerAPI({ action: "status", orders: pids.join(",") });

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

    const data = await providerAPI({ action: "refill", order: order.providerOrderId });
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
    const data = await providerAPI({ action: "status", order: order.providerOrderId });

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
      const syncData = await providerAPI({ action: "status", order: order.providerOrderId });
      freshRemains   = parseFloat(syncData.remains || 0);
      order.remains  = freshRemains;
      order.status   = syncData.status || order.status;
      console.log(`[CANCEL] Pre-cancel sync: status=${syncData.status} remains=${freshRemains}`);
    } catch (syncErr) {
      console.warn("[CANCEL] Pre-cancel sync failed (continuing anyway):", syncErr.message);
    }

    // ── 3. Call JAP cancel API ───────────────────────────
    console.log(`[CANCEL] Calling JAP cancel for order #${order.providerOrderId}`);
    const providerResponse = await providerAPI({
      action: "cancel",
      orders: String(order.providerOrderId),   // JAP uses "orders" (plural) even for single
    });
    console.log("[CANCEL] JAP response:", JSON.stringify(providerResponse));

    // ── 4. Parse JAP cancel response ────────────────────
    // JAP returns: [{ order: <id>, cancel: 1 }]  or  [{ order: <id>, cancel: { error: "..." } }]
    let cancelSuccess = false;
    let japErrMsg     = "";

    if (Array.isArray(providerResponse)) {
      const entry = providerResponse.find(r => String(r.order) === String(order.providerOrderId))
                 || providerResponse[0];
      if (entry) {
        if (entry.cancel === 1 || entry.cancel === "1") {
          cancelSuccess = true;
        } else if (entry.cancel && typeof entry.cancel === "object" && entry.cancel.error) {
          japErrMsg = entry.cancel.error;
        } else if (entry.cancel) {
          cancelSuccess = true;   // numeric non-error value = success
        }
      }
    } else if (providerResponse && typeof providerResponse === "object") {
      // Some panels return a single object
      if (providerResponse.cancel === 1 || providerResponse.cancel === "1") cancelSuccess = true;
      else if (providerResponse.error) japErrMsg = providerResponse.error;
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
   ADMIN — Filter Settings + Service Manager
══════════════════════════════════════════════════════════ */

app.get("/api/admin/filter-settings", adminGuard, async (req, res) => {
  try {
    const s    = await FilterSettings.findOne().lean() || { mode: "all", customCategories: {} };
    const cats = await ServiceCache.distinct("category");
    res.json({ mode: s.mode, customCategories: s.customCategories || {}, categories: cats });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.put("/api/admin/filter-settings", adminGuard, async (req, res) => {
  try {
    const { mode, customCategories } = req.body;
    const allowed = ["all","whitelist","blacklist"];
    if (mode && !allowed.includes(mode))
      return res.status(400).json({ message: "mode must be all/whitelist/blacklist" });
    const update = {};
    if (mode !== undefined)             update.mode            = mode;
    if (customCategories !== undefined) update.customCategories = customCategories;
    const doc = await FilterSettings.findOneAndUpdate(
      {}, { $set: update }, { upsert: true, new: true }
    );
    res.json({ message: "Settings saved", settings: doc });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.get("/api/admin/services-cache", adminGuard, async (req, res) => {
  try {
    const page      = Math.max(1, parseInt(req.query.page)  || 1);
    const limit     = Math.min(50, parseInt(req.query.limit) || 30);
    const q         = (req.query.q || "").toLowerCase();
    const catFilter = req.query.category || "";
    let filter = {};
    if (q) filter.$or = [
      { service_id: { $regex: q, $options: "i" } },
      { name:       { $regex: q, $options: "i" } },
    ];
    if (catFilter) filter.category = catFilter;
    const [services, total, overrides] = await Promise.all([
      ServiceCache.find(filter).sort({ service_id: 1 })
        .skip((page-1)*limit).limit(limit).lean(),
      ServiceCache.countDocuments(filter),
      ServiceOverride.find({}).lean(),
    ]);
    const oMap = {};
    overrides.forEach(o => { oMap[o.service_id] = o; });
    const result = services.map(s => ({ ...s, override: oMap[s.service_id] || null }));
    res.json({ services: result, total, page, pages: Math.ceil(total/limit) });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.post("/api/admin/service-overrides", adminGuard, async (req, res) => {
  try {
    const { service_id, custom_name, custom_category,
            whitelisted, blacklisted, sort_order } = req.body;
    if (!service_id) return res.status(400).json({ message: "service_id required" });
    const setFields = {};
    if (custom_name     !== undefined) setFields.custom_name     = custom_name     || null;
    if (custom_category !== undefined) setFields.custom_category = custom_category || null;
    if (whitelisted     !== undefined) setFields.whitelisted      = !!whitelisted;
    if (blacklisted     !== undefined) setFields.blacklisted      = !!blacklisted;
    if (sort_order      !== undefined) setFields.sort_order       = sort_order      || 999;
    const doc = await ServiceOverride.findOneAndUpdate(
      { service_id: String(service_id) },
      { $set: setFields },
      { upsert: true, new: true }
    );
    res.json({ message: "Saved", override: doc });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

app.delete("/api/admin/service-overrides/:service_id", adminGuard, async (req, res) => {
  try {
    await ServiceOverride.deleteOne({ service_id: req.params.service_id });
    res.json({ message: "Override removed" });
  } catch(e) { res.status(500).json({ message: e.message }); }
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



/* POST /api/admin/resync-services
   Clears ALL cached services and fetches fresh from Secsers  */
app.post("/api/admin/resync-services", adminGuard, async (req, res) => {
  try {
    const deleted = await ServiceCache.deleteMany({});
    console.log(`[RESYNC] Cleared ${deleted.deletedCount} cached services`);
    // Trigger background sync immediately
    syncServicesFromJAP();   // function name kept for compatibility
    res.json({
      message: `Cache cleared (${deleted.deletedCount} services removed). Fresh sync started — wait 30-60 seconds then refresh.`,
      cleared: deleted.deletedCount,
    });
  } catch(e) { res.status(500).json({ message: e.message }); }
});

/* ════════════════════════════════════════════════════════
   404 + Global Error Handler
════════════════════════════════════════════════════════ */
app.use((_, res) => res.status(404).json({ message: "Route not found" }));
app.use((err, req, res, next) => {           // eslint-disable-line no-unused-vars
  console.error("[ERR]", err.message);
  res.status(err.status || 500).json({ message: err.message || "Internal server error" });
});




/* ══════════════════════════════════════════════════════════
   START
══════════════════════════════════════════════════════════ */
mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () => console.log(`🚀  Server on port ${PORT} | Provider: Secsers`));

    // ── JAP Cleanup: remove JAP services from DB ──────────
    await removeJAPServices();

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
