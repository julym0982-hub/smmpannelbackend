"use strict";
require("dotenv").config();

const express   = require("express");
const cors      = require("cors");
const mongoose  = require("mongoose");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const axios     = require("axios");
const qs        = require("querystring"); // Node built-in, no install needed

/* ══════════════════════════════════════════════════════════
   ENVIRONMENT VARIABLES
══════════════════════════════════════════════════════════ */
const PORT            = process.env.PORT            || 5000;
const MONGODB_URI     = process.env.MONGODB_URI;
const JWT_SECRET      = process.env.JWT_SECRET;
const BROTHER_API_KEY = process.env.BROTHER_API_KEY || "";
const BROTHER_API_URL = process.env.BROTHER_API_URL || "https://brothersmm.com/api";
const MMK_RATE        = parseFloat(process.env.MMK_RATE || "2200");
const MARKUP          = parseFloat(process.env.MARKUP   || "1.2");

/* Validate required env vars at startup */
if (!MONGODB_URI) { console.error("❌  MONGODB_URI missing"); process.exit(1); }
if (!JWT_SECRET)  { console.error("❌  JWT_SECRET missing");  process.exit(1); }
if (!BROTHER_API_KEY) console.warn("⚠️   BROTHER_API_KEY not set — provider calls will fail");

const app = express();

/* ══════════════════════════════════════════════════════════
   CORS
══════════════════════════════════════════════════════════ */
app.use(cors({
  origin: [
    "https://smmpannelfrontend.vercel.app",
    /\.vercel\.app$/,
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
  ],
  methods:        ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials:    true,
}));

app.use(express.json());

/* ══════════════════════════════════════════════════════════
   MONGOOSE SCHEMAS
══════════════════════════════════════════════════════════ */

/* ── User ──────────────────────────────────────────────── */
const userSchema = new mongoose.Schema({
  name:         { type: String,  required: true, trim: true },
  email:        { type: String,  required: true, unique: true,
                  lowercase: true, trim: true },
  password:     { type: String,  required: true },
  balance:      { type: Number,  default: 0 },      // MMK (Kyats)
  balanceSpent: { type: Number,  default: 0 },
  totalOrders:  { type: Number,  default: 0 },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ── Order ─────────────────────────────────────────────── */
const orderSchema = new mongoose.Schema({
  user:             { type: mongoose.Schema.Types.ObjectId,
                      ref: "User", required: true },
  providerOrderId:  { type: Number,  default: null },
  serviceId:        { type: String,  required: true },
  serviceName:      { type: String,  default: "" },
  category:         { type: String,  default: "" },
  link:             { type: String,  required: true },
  quantity:         { type: Number,  required: true },
  chargeMMK:        { type: Number,  required: true },
  chargeUSD:        { type: Number,  default: 0 },
  status:           { type: String,  default: "Pending" },
  startCount:       { type: String,  default: "0" },
  remains:          { type: Number,  default: 0 },
  refundedAmount:   { type: Number,  default: 0 },
  providerError:    { type: String,  default: null },
}, { timestamps: true });

const Order = mongoose.model("Order", orderSchema);

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

/* ══════════════════════════════════════════════════════════
   AUTH MIDDLEWARE  (fix: split on space, robust extraction)
══════════════════════════════════════════════════════════ */
function guard(req, res, next) {
  try {
    const authHeader = req.headers["authorization"] || req.headers["Authorization"] || "";

    if (!authHeader || authHeader.trim() === "") {
      return res.status(401).json({ message: "Authorization header missing" });
    }

    // Support both "Bearer <token>" and raw token
    const parts = authHeader.trim().split(/\s+/);
    const token  = parts.length === 2 && parts[0].toLowerCase() === "bearer"
      ? parts[1]   // standard: "Bearer eyJ..."
      : parts[0];  // fallback: raw token sent without "Bearer"

    if (!token) {
      return res.status(401).json({ message: "Token not provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.uid = decoded.id;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired, please log in again" });
    }
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid token, please log in again" });
    }
    return res.status(401).json({ message: "Authentication failed" });
  }
}

/* ══════════════════════════════════════════════════════════
   BROTHER SMM API HELPER
   ─────────────────────────────────────────────────────────
   Correct parameter names (Brother SMM standard):
     key      → API key
     action   → add | services | status | mass_status | ...
     service  → Service ID  (for add)
     link     → URL         (for add)
     quantity → Quantity    (for add)
     order    → Order ID    (for status / cancel / refill)
   Format: application/x-www-form-urlencoded (NOT JSON)
══════════════════════════════════════════════════════════ */
async function brotherAPI(params) {
  // ── Build Form Data payload ──────────────────────────
  const payload = new URLSearchParams();
  payload.append("key",    process.env.BROTHER_API_KEY);
  payload.append("action", params.action);

  if (params.action === "add") {
    payload.append("service",  String(params.service));
    payload.append("link",     String(params.link));
    payload.append("quantity", String(params.quantity));
    if (params.runs)     payload.append("runs",     String(params.runs));
    if (params.interval) payload.append("interval", String(params.interval));
  }

  if (["status","cancel","refill","mass_status"].includes(params.action)) {
    payload.append("order", String(params.order));
  }

  // ── Log outgoing request ─────────────────────────────
  const url = process.env.BROTHER_API_URL || "https://brothersmm.com/api";
  console.log("━━━ [BrotherSMM] REQUEST ━━━");
  console.log("URL     :", url);
  console.log("Payload :", Object.fromEntries(payload));

  try {
    const { status, data } = await axios.post(
      url,
      payload.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent":   "Mozilla/5.0 (compatible; SMM-Panel/1.0)",
        },
        timeout: 25000,
      }
    );

    // ── Log success response ─────────────────────────────
    console.log("━━━ [BrotherSMM] RESPONSE ━━━");
    console.log("HTTP Status :", status);
    console.log("Body        :", JSON.stringify(data));

    // Provider errors arrive as HTTP 200 with { error: "..." }
    if (data && data.error) {
      console.error("[BrotherSMM] Provider error:", data.error);
      throw new Error(String(data.error));
    }

    return data;

  } catch (err) {
    // ── Log error detail ─────────────────────────────────
    console.error("━━━ [BrotherSMM] ERROR ━━━");

    if (err.response) {
      console.error("HTTP Status  :", err.response.status);
      console.error("Response Body:", JSON.stringify(err.response.data));
      const msg = err.response.data?.error
               || err.response.data?.message
               || `HTTP ${err.response.status}`;
      throw new Error("[BrotherSMM] " + msg);
    }

    if (err.request) {
      console.error("No response — timeout or network error");
      throw new Error("[BrotherSMM] No response from provider (timeout/network)");
    }

    console.error("Error:", err.message);
    if (err.message.startsWith("[BrotherSMM]")) throw err;
    throw new Error("[BrotherSMM] " + err.message);
  }
}

/* ══════════════════════════════════════════════════════════
   ROUTES — AUTH
══════════════════════════════════════════════════════════ */

app.get("/", (_, res) => res.json({ status: "running", time: new Date() }));

/* SIGNUP */
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

    console.log("[SIGNUP]", email);
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

/* LOGIN */
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

    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ message: "Invalid username or password" });

    console.log("[LOGIN]", user.email);
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

/* RESET PASSWORD */
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

    await User.updateOne({ email }, {
      $set: { password: await bcrypt.hash(newPassword, 12) },
    });

    console.log("[RESET]", email);
    res.json({ message: "Password reset successfully. You can now log in." });
  } catch (e) {
    console.error("[RESET ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ME — current user info */
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

/* CHANGE PASSWORD */
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

    await User.updateOne({ _id: req.uid }, {
      $set: { password: await bcrypt.hash(newPassword, 12) },
    });

    console.log("[CHPW]", user.email);
    res.json({ message: "Password changed successfully" });
  } catch (e) {
    console.error("[CHPW ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — PROVIDER (Brother SMM passthrough)
══════════════════════════════════════════════════════════ */

/*
 * GET /api/provider/services
 *
 * Brother SMM returns an Object (key=service_id, value=service details).
 * We convert it to a sorted Array for the frontend.
 * Cached 10 minutes to avoid rate-limiting.
 */
let _servicesCache   = null;
let _servicesCachedAt = 0;

app.get("/api/provider/services", guard, async (req, res) => {
  try {
    const now = Date.now();
    const forceRefresh = req.query.refresh === "1";

    if (!forceRefresh && _servicesCache && (now - _servicesCachedAt) < 10 * 60 * 1000) {
      return res.json(_servicesCache);
    }

    // Fetch from Brother SMM — actionType: "services"
    const raw = await brotherAPI({ action: "services" });

    /*
     * Brother SMM response format (Object, NOT Array):
     * {
     *   "8":  { service_id:"8", name:"...", category:"Facebook", price:"10", ... },
     *   "11": { service_id:"11", ... },
     *   ...
     * }
     * Convert to Array sorted by service_id (numeric).
     */
    let servicesArray;

    if (Array.isArray(raw)) {
      // Some panels return an Array directly
      servicesArray = raw;
    } else if (typeof raw === "object" && raw !== null) {
      // Object → Array conversion
      servicesArray = Object.values(raw).map(svc => ({
        service_id:  String(svc.service_id || svc.id || ""),
        name:        svc.name        || "",
        type:        svc.type        || "default",
        price:       svc.price       || "0",
        min_amount:  svc.min_amount  || "10",
        max_amount:  svc.max_amount  || "10000000",
        description: svc.description || "",
        category:    svc.category    || "Other",
        avg_time:    svc.avg_time    || null,
      }));

      // Sort numerically by service_id
      servicesArray.sort((a, b) =>
        parseInt(a.service_id) - parseInt(b.service_id)
      );
    } else {
      return res.status(502).json({ message: "Unexpected response from provider" });
    }

    // Cache and return
    _servicesCache    = servicesArray;
    _servicesCachedAt = now;

    console.log(`[SERVICES] Fetched ${servicesArray.length} services`);
    res.json(servicesArray);

  } catch (e) {
    console.error("[SERVICES ERR]", e.message);
    res.status(502).json({ message: e.message });
  }
});

/*
 * GET /api/provider/balance
 * Returns Brother SMM USD balance.
 */
app.get("/api/provider/balance", guard, async (req, res) => {
  try {
    const data = await brotherAPI({ action: "balance" });
    res.json(data);
  } catch (e) {
    console.error("[BAL ERR]", e.message);
    res.status(502).json({ message: e.message });
  }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — ORDERS
══════════════════════════════════════════════════════════ */

/*
 * POST /api/orders
 * Place order → deduct balance → call Brother SMM → save to DB.
 *
 * Body: { serviceId, serviceName, category, link, quantity, chargeMMK }
 */
app.post("/api/orders", guard, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { serviceId, serviceName, category, link, quantity, chargeMMK } = req.body;

    // Validate
    if (!serviceId || !link || !quantity || !chargeMMK)
      return res.status(400).json({
        message: "serviceId, link, quantity, chargeMMK are required",
      });
    if (quantity < 1)
      return res.status(400).json({ message: "Quantity must be at least 1" });
    if (chargeMMK <= 0)
      return res.status(400).json({ message: "Invalid charge amount" });

    // Check user balance
    const user = await User.findById(req.uid).session(session);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.balance < chargeMMK)
      return res.status(400).json({
        message: `Insufficient balance. Need ${chargeMMK} Ks, have ${user.balance} Ks`,
      });

    // Deduct balance
    user.balance      -= chargeMMK;
    user.balanceSpent += chargeMMK;
    user.totalOrders  += 1;
    await user.save({ session });

    // Create order record
    const chargeUSD = parseFloat((chargeMMK / MMK_RATE).toFixed(4));
    const [order]   = await Order.create([{
      user: req.uid,
      serviceId,
      serviceName: serviceName || "",
      category:    category    || "",
      link,
      quantity,
      chargeMMK,
      chargeUSD,
      status: "Processing",
    }], { session });

    // Call Brother SMM — actionType: "add"
    let providerRes;
    try {
      providerRes = await brotherAPI({
        action:   "add",        // ✅ correct param
        service:  serviceId,    // ✅ "service" not "orderType"
        link:     link,         // ✅ "link"  not "orderUrl"
        quantity: quantity,     // ✅ "quantity" not "orderQuantity"
      });
    } catch (provErr) {
      // Refund on provider failure
      user.balance      += chargeMMK;
      user.balanceSpent -= chargeMMK;
      user.totalOrders  -= 1;
      await user.save({ session });
      order.status        = "Failed";
      order.providerError = provErr.message;
      await order.save({ session });
      await session.commitTransaction();
      session.endSession();
      console.error("[ORDER] Provider rejected:", provErr.message);
      return res.status(502).json({ message: provErr.message });
    }

    // Save provider orderID
    order.providerOrderId = providerRes.orderID;
    order.status          = "Pending";
    await order.save({ session });

    await session.commitTransaction();
    session.endSession();

    console.log(`[ORDER] Created ${order._id} → provider #${providerRes.orderID}`);
    res.status(201).json({
      message:          "Order placed successfully",
      orderId:          order._id,
      providerOrderId:  providerRes.orderID,
      remainingBalance: user.balance,
      order: {
        id:          order._id,
        serviceId,
        serviceName: serviceName || "",
        category:    category    || "",
        link,
        quantity,
        chargeMMK,
        status:      order.status,
        createdAt:   order.createdAt,
      },
    });

  } catch (e) {
    await session.abortTransaction();
    session.endSession();
    console.error("[ORDER ERR]", e.message);
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/*
 * GET /api/orders
 * User's order history. Query: ?page=1&limit=20&status=Pending
 */
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

    res.json({
      orders,
      pagination: { page, limit, total, pages: Math.ceil(total/limit) },
    });
  } catch (e) {
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/*
 * GET /api/orders/:id
 */
app.get("/api/orders/:id", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    res.json(order);
  } catch (e) {
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/*
 * POST /api/orders/:id/sync-status
 * Fetch latest status from Brother SMM (actionType: "status").
 */
app.post("/api/orders/:id/sync-status", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId)
      return res.status(400).json({ message: "No provider order ID" });

    const data = await brotherAPI({
      action: "status",               // ✅
      order:  order.providerOrderId,  // ✅ "order" not "orderID"
    });

    order.status         = data.orderStatus              || order.status;
    order.startCount     = data.startCount               || order.startCount;
    order.remains        = parseFloat(data.remaining_amount || 0);
    order.refundedAmount = parseFloat(data.refunded_amount  || 0);
    await order.save();

    res.json({ message: "Status synced", order, providerData: data });
  } catch (e) {
    console.error("[SYNC ERR]", e.message);
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/sync-bulk
 * Mass status check (actionType: "mass_status") — up to 100 orders.
 * Body: { orderIds: ["dbId1",...] }
 */
app.post("/api/orders/sync-bulk", guard, async (req, res) => {
  try {
    const { orderIds } = req.body;
    if (!Array.isArray(orderIds) || !orderIds.length)
      return res.status(400).json({ message: "orderIds array required" });
    if (orderIds.length > 100)
      return res.status(400).json({ message: "Max 100 orders per request" });

    const orders      = await Order.find({ _id: { $in: orderIds }, user: req.uid });
    const providerIds = orders.map(o => o.providerOrderId).filter(Boolean);
    if (!providerIds.length)
      return res.json({ message: "No provider IDs found", updated: 0 });

    const data = await brotherAPI({
      action: "mass_status",           // ✅
      order:  providerIds.join(","),   // ✅ "order" not "orderID"
    });

    let updated = 0;
    for (const order of orders) {
      const d = data[order.providerOrderId];
      if (!d) continue;
      order.status         = d.orderStatus              || order.status;
      order.startCount     = d.startCount               || order.startCount;
      order.remains        = parseFloat(d.remaining_amount || 0);
      order.refundedAmount = parseFloat(d.refunded_amount  || 0);
      await order.save();
      updated++;
    }
    res.json({ message: `${updated} orders updated`, updated });
  } catch (e) {
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/:id/refill  (actionType: "refill")
 */
app.post("/api/orders/:id/refill", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId)
      return res.status(400).json({ message: "No provider order ID" });

    const data = await brotherAPI({
      action: "refill",               // ✅
      order:  order.providerOrderId,  // ✅
    });

    order.status = "Refill Requested";
    await order.save();
    res.json({ message: data.message || "Refill requested", providerResponse: data });
  } catch (e) {
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/:id/cancel  (actionType: "cancel")
 * Auto-refund proportional to remaining quantity.
 */
app.post("/api/orders/:id/cancel", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId)
      return res.status(400).json({ message: "No provider order ID" });
    if (["Completed","Cancelled"].includes(order.status))
      return res.status(400).json({ message: "Order cannot be cancelled" });

    const data = await brotherAPI({
      action: "cancel",               // ✅
      order:  order.providerOrderId,  // ✅
    });

    order.status = "Cancelled";
    await order.save();

    // Partial refund if remains > 0
    let refundMMK = 0;
    if (order.remains > 0 && order.quantity > 0) {
      const ratio   = order.remains / order.quantity;
      refundMMK     = Math.floor(order.chargeMMK * ratio);
      if (refundMMK > 0) {
        await User.findByIdAndUpdate(req.uid, {
          $inc: { balance: refundMMK, balanceSpent: -refundMMK },
        });
      }
    }

    res.json({
      message:          data.message || "Order cancelled",
      refundMMK,
      providerResponse: data,
    });
  } catch (e) {
    res.status(502).json({ message: e.message });
  }
});

/* ══════════════════════════════════════════════════════════
   404
══════════════════════════════════════════════════════════ */
app.use((_, res) => res.status(404).json({ message: "Route not found" }));

/* ══════════════════════════════════════════════════════════
   START SERVER
══════════════════════════════════════════════════════════ */
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () =>
      console.log(`🚀  Server running on port ${PORT}`)
    );
  })
  .catch(e => {
    console.error("❌  MongoDB:", e.message);
    process.exit(1);
  });
