"use strict";
require("dotenv").config();

const express   = require("express");
const cors      = require("cors");
const mongoose  = require("mongoose");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const axios     = require("axios");
const multer    = require("multer");

/* multer — memory storage (no disk needed on Render/Vercel) */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },   // 5 MB max
  fileFilter: (_, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files are allowed"));
  },
});

/* ══════════════════════════════════════════════════════════
   ENV VARS
══════════════════════════════════════════════════════════ */
const PORT        = process.env.PORT        || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET;
const JAP_API_KEY   = process.env.JAP_API_KEY   || "";
const JAP_API_URL   = process.env.JAP_API_URL   || "https://justanotherpanel.com/api/v2";
const MMK_RATE      = parseFloat(process.env.MMK_RATE || "4500");
const MARKUP        = parseFloat(process.env.MARKUP   || "1.2");
const IMGBB_API_KEY = process.env.IMGBB_API_KEY || "";
// Comma-separated admin emails: admin@example.com,admin2@example.com
const ADMIN_EMAILS  = (process.env.ADMIN_EMAILS || "").split(",")
  .map(e => e.trim().toLowerCase()).filter(Boolean);

if (!MONGODB_URI)    { console.error("❌  MONGODB_URI missing"); process.exit(1); }
if (!JWT_SECRET)     { console.error("❌  JWT_SECRET missing");  process.exit(1); }
if (!JAP_API_KEY)     console.warn("⚠️  JAP_API_KEY not set");
if (!IMGBB_API_KEY)   console.warn("⚠️  IMGBB_API_KEY not set — deposits won't work");

const app = express();

/* ══════════════════════════════════════════════════════════
   CORS
══════════════════════════════════════════════════════════ */
app.use(cors({
  origin: [/\.vercel\.app$/, "http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500"],
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials: true,
}));
app.use(express.json());

/* ══════════════════════════════════════════════════════════
   SCHEMAS
══════════════════════════════════════════════════════════ */
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:     { type: String, required: true },
  balance:      { type: Number, default: 0 },
  balanceSpent: { type: Number, default: 0 },
  totalOrders:  { type: Number, default: 0 },
  isAdmin:      { type: Boolean, default: false },
}, { timestamps: true });
const User = mongoose.model("User", userSchema);

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
const Order = mongoose.model("Order", orderSchema);

/* ── PaymentRequest (Deposit) ─────────────────────────── */
const paymentSchema = new mongoose.Schema({
  user:          { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  username:      { type: String,  default: "" },
  email:         { type: String,  default: "" },
  amount:        { type: Number,  required: true },
  creditAmount:  { type: Number,  default: 0 },
  screenshotUrl: { type: String,  required: true },
  status:        { type: String,  enum: ["pending","approved","rejected"], default: "pending" },
  note:          { type: String,  default: "" },
  approvedBy:    { type: String,  default: "" },
}, { timestamps: true });
const PaymentRequest = mongoose.model("PaymentRequest", paymentSchema);


/* ══════════════════════════════════════════════════════════
   HELPERS
══════════════════════════════════════════════════════════ */
const makeToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });

const safeUser = (u) => ({
  id: u._id, name: u.name, email: u.email,
  balance: u.balance, balanceSpent: u.balanceSpent,
  totalOrders: u.totalOrders, createdAt: u.createdAt,
  isAdmin: u.isAdmin || false,
});

const normEmail = (e) => String(e || "").toLowerCase().trim();

/* ── Auth middleware ─────────────────────────────────────*/
function guard(req, res, next) {
  try {
    const authHeader = req.headers["authorization"] || "";
    if (!authHeader) return res.status(401).json({ message: "Authorization header missing" });
    const parts = authHeader.trim().split(/\s+/);
    const token = (parts.length === 2 && parts[0].toLowerCase() === "bearer") ? parts[1] : parts[0];
    if (!token) return res.status(401).json({ message: "Token not provided" });
    req.uid = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError")
      return res.status(401).json({ message: "Token expired, please log in again" });
    return res.status(401).json({ message: "Invalid token, please log in again" });
  }
}

/* ── Admin guard ────────────────────────────────────────────*/
async function adminGuard(req, res, next) {
  try {
    const authHeader = req.headers["authorization"] || "";
    if (!authHeader) return res.status(401).json({ message: "Authorization header missing" });
    const parts = authHeader.trim().split(/\s+/);
    const token = (parts.length === 2 && parts[0].toLowerCase() === "bearer") ? parts[1] : parts[0];
    if (!token) return res.status(401).json({ message: "Token not provided" });
    req.uid = jwt.verify(token, JWT_SECRET).id;
    const user = await User.findById(req.uid);
    if (!user) return res.status(404).json({ message: "User not found" });
    const isAdmin = user.isAdmin || ADMIN_EMAILS.includes(user.email.toLowerCase());
    if (!isAdmin) return res.status(403).json({ message: "Admin access required" });
    req.adminUser = user;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError")
      return res.status(401).json({ message: "Token expired" });
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ── ImgBB upload ────────────────────────────────────────────
   Uploads buffer to ImgBB, returns public image URL           */
async function uploadToImgBB(buffer) {
  if (!IMGBB_API_KEY) throw new Error("IMGBB_API_KEY not configured on server");
  const base64 = buffer.toString("base64");
  const params = new URLSearchParams();
  params.append("key",   IMGBB_API_KEY);
  params.append("image", base64);
  const { data } = await axios.post("https://api.imgbb.com/1/upload", params.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 30000,
  });
  if (!data.success) throw new Error("ImgBB upload failed: " + JSON.stringify(data.error || data));
  return data.data.url;  // direct image URL
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
async function japAPI(params, _retry = false) {
  const payload = new URLSearchParams();
  payload.append("key",    JAP_API_KEY);
  payload.append("action", params.action);

  // Add order
  if (params.action === "add") {
    payload.append("service",  String(params.service));
    payload.append("link",     String(params.link));
    payload.append("quantity", String(params.quantity));
    if (params.runs)      payload.append("runs",      String(params.runs));
    if (params.interval)  payload.append("interval",  String(params.interval));
    if (params.comments)  payload.append("comments",  String(params.comments)); // Custom Comments
  }

  // Single order operations (status / refill)
  if (["status", "refill"].includes(params.action) && params.order) {
    payload.append("order", String(params.order));
  }

  // Multiple orders (status with orders / cancel / refill with orders)
  if (params.orders) {
    payload.append("orders", String(params.orders));
  }

  // ── Log request ─────────────────────────────────────────
  console.log("━━━ [JAP] REQUEST ━━━");
  console.log("URL     :", JAP_API_URL);
  console.log("Payload :", Object.fromEntries(payload));

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
          "Cache-Control":    "no-cache",
          "Pragma":           "no-cache",
        },
        timeout: 25000,
      }
    );

    console.log("━━━ [JAP] RESPONSE ━━━");
    console.log("HTTP Status :", status);
    console.log("Body        :", JSON.stringify(data));

    if (data && data.error) {
      console.error("[JAP] Provider error:", data.error);
      throw new Error(String(data.error));
    }
    return data;

  } catch (err) {
    console.error("━━━ [JAP] ERROR ━━━");
    if (err.response) {
      console.error("HTTP Status  :", err.response.status);
      console.error("Response Body:", JSON.stringify(err.response.data));
      const retryable = [403, 429, 503].includes(err.response.status);
      if (retryable && !_retry) {
        const wait = err.response.status === 429 ? 3000 : 1000;
        console.log(`[JAP] Retrying in ${wait}ms (status ${err.response.status})...`);
        await new Promise(r => setTimeout(r, wait));
        return japAPI(params, true);
      }
      const msg = err.response.data?.error || err.response.data?.message || `HTTP ${err.response.status}`;
      throw new Error("[JAP] " + msg);
    }
    if (err.request) {
      if (!_retry) {
        console.log("[JAP] Timeout — retrying in 1s...");
        await new Promise(r => setTimeout(r, 1000));
        return japAPI(params, true);
      }
      throw new Error("[JAP] No response from provider (timeout/network)");
    }
    if (err.message.startsWith("[JAP]")) throw err;
    throw new Error("[JAP] " + err.message);
  }
}

/* ══════════════════════════════════════════════════════════
   ROUTES — AUTH
══════════════════════════════════════════════════════════ */
app.get("/", (_, res) => res.json({ status: "running", provider: "JAP", time: new Date() }));

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
    const user = await User.create({ name, email, password: await bcrypt.hash(password, 12) });
    res.status(201).json({ message: "Account created", token: makeToken(user._id), user: safeUser(user) });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { password } = req.body;
    const input = String(req.body.email || req.body.username || "").trim();
    if (!input || !password)
      return res.status(400).json({ message: "Please fill in all fields" });
    const user = await User.findOne({
      $or: [{ email: input.toLowerCase() }, { name: { $regex: `^${input}$`, $options: "i" } }],
    });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ message: "Invalid username or password" });
    res.json({ message: "Login successful", token: makeToken(user._id), user: safeUser(user) });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { newPassword } = req.body;
    const email = normEmail(req.body.email);
    if (!email || !newPassword)
      return res.status(400).json({ message: "Email and new password are required" });
    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "No account found with this email" });
    await User.updateOne({ email }, { $set: { password: await bcrypt.hash(newPassword, 12) } });
    res.json({ message: "Password reset successfully. You can now log in." });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
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
let _svcCache = null, _svcCachedAt = 0;

app.get("/api/provider/services", guard, async (req, res) => {
  try {
    const now = Date.now();
    if (_svcCache && (now - _svcCachedAt) < 10 * 60 * 1000 && req.query.refresh !== "1")
      return res.json(_svcCache);

    const raw = await japAPI({ action: "services" });

    // JAP always returns Array — normalize to consistent shape
    const arr = (Array.isArray(raw) ? raw : Object.values(raw)).map(s => ({
      service_id:  String(s.service || s.service_id || ""),  // unified ID field
      name:        s.name        || "",
      type:        s.type        || "Default",
      category:    s.category    || "Other",
      rate:        s.rate        || "0",        // USD per 1000 (JAP uses "rate")
      min:         String(s.min  || "10"),      // JAP: min (not min_amount)
      max:         String(s.max  || "10000000"),// JAP: max (not max_amount)
      refill:      s.refill      || false,
      cancel:      s.cancel      || false,
    }));

    arr.sort((a, b) => parseInt(a.service_id) - parseInt(b.service_id));
    _svcCache = arr; _svcCachedAt = now;
    console.log(`[SERVICES] ${arr.length} JAP services loaded`);
    res.json(arr);
  } catch (e) {
    console.error("[SERVICES ERR]", e.message);
    res.status(502).json({ message: e.message });
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
      Order.find(filter).sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit),
      Order.countDocuments(filter),
    ]);
    res.json({ orders, pagination: { page, limit, total, pages: Math.ceil(total/limit) } });
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
});

/* GET /api/orders/:id */
app.get("/api/orders/:id", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    res.json(order);
  } catch (e) { res.status(500).json({ message: "Server error: " + e.message }); }
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
 * POST /api/orders/:id/cancel
 * JAP: action=cancel, orders=id1,id2  (plural "orders")
 * Response: [{ order: 9, cancel: { error: "..." } }, { order: 2, cancel: 1 }]
 */
app.post("/api/orders/:id/cancel", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId) return res.status(400).json({ message: "No provider order ID" });
    if (["Completed","Canceled","Cancelled"].includes(order.status))
      return res.status(400).json({ message: "Order cannot be cancelled" });

    // JAP cancel uses "orders" (plural) even for single
    const data = await japAPI({ action: "cancel", orders: String(order.providerOrderId) });

    order.status = "Canceled";  // JAP uses "Canceled" (single l)
    await order.save();

    // Partial refund if remains > 0
    let refundMMK = 0;
    if (order.remains > 0 && order.quantity > 0) {
      refundMMK = Math.floor(order.chargeMMK * (order.remains / order.quantity));
      if (refundMMK > 0)
        await User.findByIdAndUpdate(req.uid, { $inc: { balance: refundMMK, balanceSpent: -refundMMK } });
    }
    res.json({ message: "Order canceled", refundMMK, providerResponse: data });
  } catch (e) { res.status(502).json({ message: e.message }); }
});

/* ══════════════════════════════════════════════════════════
   404
══════════════════════════════════════════════════════════ */
app.use((_, res) => res.status(404).json({ message: "Route not found" }));

/* ══════════════════════════════════════════════════════════
   START
══════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════
   ROUTES — DEPOSIT (User)
══════════════════════════════════════════════════════════ */
app.post("/api/deposit/request", guard, upload.single("screenshot"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "Screenshot is required" });
    const amount = parseInt(req.body.amount);
    if (!amount || amount < 1000)
      return res.status(400).json({ message: "Minimum deposit amount is 1,000 Ks" });
    const screenshotUrl = await uploadToImgBB(req.file.buffer);
    const user = await User.findById(req.uid);
    const payment = await PaymentRequest.create({
      user: req.uid, username: user.name, email: user.email,
      amount, screenshotUrl, status: "pending",
    });
    console.log("[DEPOSIT] Created:", payment._id, "by", user.email);
    res.status(201).json({
      message: "Deposit request submitted! Admin will review and approve shortly.",
      requestId: payment._id,
    });
  } catch (e) { console.error("[DEPOSIT ERR]", e.message); res.status(500).json({ message: e.message }); }
});

app.get("/api/deposit/history", guard, async (req, res) => {
  try {
    const list = await PaymentRequest.find({ user: req.uid }).sort({ createdAt: -1 }).limit(20);
    res.json(list);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — ADMIN
══════════════════════════════════════════════════════════ */
app.get("/api/admin/me", adminGuard, async (req, res) => {
  res.json({ isAdmin: true, email: req.adminUser.email });
});

app.get("/api/admin/deposits", adminGuard, async (req, res) => {
  try {
    const status = req.query.status || "pending";
    const list = await PaymentRequest.find({ status })
      .populate("user", "name email balance")
      .sort({ createdAt: -1 });
    res.json(list);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post("/api/admin/deposits/:id/approve", adminGuard, async (req, res) => {
  try {
    const creditAmount = parseInt(req.body.creditAmount);
    if (!creditAmount || creditAmount < 1)
      return res.status(400).json({ message: "creditAmount must be >= 1 Ks" });
    const payment = await PaymentRequest.findById(req.params.id).populate("user");
    if (!payment) return res.status(404).json({ message: "Request not found" });
    if (payment.status !== "pending") return res.status(400).json({ message: "Already processed" });
    const updatedUser = await User.findByIdAndUpdate(
      payment.user._id, { $inc: { balance: creditAmount } }, { new: true });
    payment.status = "approved"; payment.creditAmount = creditAmount;
    payment.approvedBy = req.adminUser.email;
    await payment.save();
    res.json({ message: `Approved! ${creditAmount.toLocaleString()} Ks added to ${payment.username}`, newBalance: updatedUser.balance });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post("/api/admin/deposits/:id/reject", adminGuard, async (req, res) => {
  try {
    const payment = await PaymentRequest.findById(req.params.id);
    if (!payment) return res.status(404).json({ message: "Request not found" });
    if (payment.status !== "pending") return res.status(400).json({ message: "Already processed" });
    payment.status = "rejected"; payment.note = req.body.note || "Rejected by admin";
    payment.approvedBy = req.adminUser.email;
    await payment.save();
    res.json({ message: "Deposit request rejected" });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () => console.log(`🚀  Server on port ${PORT} | Provider: JAP`));
  })
  .catch(e => { console.error("❌  MongoDB:", e.message); process.exit(1); });
