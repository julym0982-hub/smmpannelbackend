"use strict";
require("dotenv").config();

const express   = require("express");
const cors      = require("cors");
const mongoose  = require("mongoose");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const axios     = require("axios");

/* ══════════════════════════════════════════════════════════
   ENVIRONMENT VARIABLES
══════════════════════════════════════════════════════════ */
const PORT             = process.env.PORT             || 5000;
const MONGODB_URI      = process.env.MONGODB_URI;
const JWT_SECRET       = process.env.JWT_SECRET       || "change_me_in_production";
const BROTHER_API_KEY  = process.env.BROTHER_API_KEY  || "";
const BROTHER_API_URL  = process.env.BROTHER_API_URL  || "https://brothersmm.com/api";
const MMK_RATE         = parseFloat(process.env.MMK_RATE || "2200"); // 1 USD = MMK_RATE Ks
const MARKUP           = parseFloat(process.env.MARKUP   || "1.2");  // 20% markup

if (!MONGODB_URI) { console.error("❌  MONGODB_URI missing"); process.exit(1); }
if (!BROTHER_API_KEY) console.warn("⚠️  BROTHER_API_KEY not set");

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
  email:        { type: String,  required: true, unique: true, lowercase: true, trim: true },
  password:     { type: String,  required: true },
  balance:      { type: Number,  default: 0 },      // in MMK (Kyats)
  balanceSpent: { type: Number,  default: 0 },
  totalOrders:  { type: Number,  default: 0 },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ── Order ─────────────────────────────────────────────── */
const orderSchema = new mongoose.Schema({
  user:             { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  // Provider info
  providerOrderId:  { type: Number,  default: null },   // Brother SMM orderID
  serviceId:        { type: String,  required: true },
  serviceName:      { type: String,  default: "" },
  category:         { type: String,  default: "" },
  // Order details
  link:             { type: String,  required: true },
  quantity:         { type: Number,  required: true },
  chargeMMK:        { type: Number,  required: true },  // charge in Kyats
  chargeUSD:        { type: Number,  default: 0 },      // approximate USD
  // Status (synced from provider)
  status:           { type: String,  default: "Pending" },
  startCount:       { type: String,  default: "0" },
  remains:          { type: Number,  default: 0 },
  refundedAmount:   { type: Number,  default: 0 },
  providerError:    { type: String,  default: null },   // error if provider rejected
}, { timestamps: true });

const Order = mongoose.model("Order", orderSchema);

/* ══════════════════════════════════════════════════════════
   HELPERS
══════════════════════════════════════════════════════════ */

const makeToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });

const safeUser  = (u)  => ({
  id:           u._id,
  name:         u.name,
  email:        u.email,
  balance:      u.balance,
  balanceSpent: u.balanceSpent,
  totalOrders:  u.totalOrders,
  createdAt:    u.createdAt,
});

const normEmail = (e) => String(e || "").toLowerCase().trim();

/* ── Auth middleware ──────────────────────────────────────── */
function guard(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer "))
    return res.status(401).json({ message: "No token provided" });
  try {
    req.uid = jwt.verify(header.slice(7), JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ message: "Token invalid or expired" });
  }
}

/* ══════════════════════════════════════════════════════════
   BROTHER SMM API HELPER
   All calls are POST with JSON body.
══════════════════════════════════════════════════════════ */
async function brotherAPI(params) {
  const payload = { apiKey: BROTHER_API_KEY, ...params };
  try {
    const { data } = await axios.post(BROTHER_API_URL, payload, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return data;
  } catch (err) {
    const msg = err.response?.data?.error || err.message || "Provider unreachable";
    throw new Error("[BrotherSMM] " + msg);
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
    res.status(201).json({ message: "Account created", token: makeToken(user._id), user: safeUser(user) });
  } catch (e) {
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
    res.json({ message: "Login successful", token: makeToken(user._id), user: safeUser(user) });
  } catch (e) {
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
    if (!user) return res.status(404).json({ message: "No account found with this email" });

    await User.updateOne({ email }, { $set: { password: await bcrypt.hash(newPassword, 12) } });
    res.json({ message: "Password reset successfully. You can now log in." });
  } catch (e) {
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ME */
app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const user = await User.findById(req.uid).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(safeUser(user));
  } catch (e) {
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

    await User.updateOne({ _id: req.uid }, { $set: { password: await bcrypt.hash(newPassword, 12) } });
    res.json({ message: "Password changed successfully" });
  } catch (e) {
    res.status(500).json({ message: "Server error: " + e.message });
  }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — PROVIDER (Brother SMM passthrough)
══════════════════════════════════════════════════════════ */

/*
 * GET /api/provider/services
 * Returns full services list from Brother SMM.
 * Cached in memory for 10 minutes to avoid rate-limits.
 */
let servicesCache = null;
let servicesCachedAt = 0;

app.get("/api/provider/services", guard, async (req, res) => {
  try {
    const now = Date.now();
    if (servicesCache && (now - servicesCachedAt) < 10 * 60 * 1000) {
      return res.json(servicesCache);
    }
    const data = await brotherAPI({ actionType: "services" });
    servicesCache   = data;
    servicesCachedAt = now;
    console.log("[SERVICES] fetched", Object.keys(data).length, "services");
    res.json(data);
  } catch (e) {
    console.error("[SERVICES ERR]", e.message);
    res.status(502).json({ message: e.message });
  }
});

/*
 * GET /api/provider/balance
 * Returns Brother SMM account balance (USD).
 * Useful for admin to monitor.
 */
app.get("/api/provider/balance", guard, async (req, res) => {
  try {
    const data = await brotherAPI({ actionType: "balance" });
    res.json(data);  // { balance, currency }
  } catch (e) {
    res.status(502).json({ message: e.message });
  }
});

/* ══════════════════════════════════════════════════════════
   ROUTES — ORDERS
══════════════════════════════════════════════════════════ */

/*
 * POST /api/orders
 * Place a new order. Deducts user balance, calls Brother SMM, stores in DB.
 *
 * Body: { serviceId, serviceName, category, link, quantity, chargeMMK }
 */
app.post("/api/orders", guard, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const { serviceId, serviceName, category, link, quantity, chargeMMK } = req.body;

    // ── Validate ─────────────────────────────────────────
    if (!serviceId || !link || !quantity || !chargeMMK)
      return res.status(400).json({ message: "serviceId, link, quantity, chargeMMK are required" });
    if (quantity < 1)
      return res.status(400).json({ message: "Quantity must be at least 1" });
    if (chargeMMK <= 0)
      return res.status(400).json({ message: "Invalid charge amount" });

    // ── Check user balance ────────────────────────────────
    const user = await User.findById(req.uid).session(session);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.balance < chargeMMK)
      return res.status(400).json({
        message: `Insufficient balance. Need ${chargeMMK} Ks, have ${user.balance} Ks`,
      });

    // ── Deduct balance (optimistic — before API call) ─────
    user.balance      -= chargeMMK;
    user.balanceSpent += chargeMMK;
    user.totalOrders  += 1;
    await user.save({ session });

    // ── Create Order record in DB ─────────────────────────
    const chargeUSD = parseFloat((chargeMMK / MMK_RATE).toFixed(4));
    const [order]   = await Order.create([{
      user:        req.uid,
      serviceId,
      serviceName: serviceName || "",
      category:    category    || "",
      link,
      quantity,
      chargeMMK,
      chargeUSD,
      status:      "Processing",
    }], { session });

    // ── Call Brother SMM API ──────────────────────────────
    let providerRes;
    try {
      providerRes = await brotherAPI({
        actionType:    "add",
        orderType:     serviceId,
        orderUrl:      link,
        orderQuantity: quantity,
      });
    } catch (provErr) {
      // Provider rejected → refund user balance
      user.balance      += chargeMMK;
      user.balanceSpent -= chargeMMK;
      user.totalOrders  -= 1;
      await user.save({ session });

      order.status        = "Failed";
      order.providerError = provErr.message;
      await order.save({ session });

      await session.commitTransaction();
      session.endSession();
      return res.status(502).json({ message: provErr.message });
    }

    // ── Save provider orderID ─────────────────────────────
    if (providerRes.error) {
      // Provider returned an error in the response body
      user.balance      += chargeMMK;
      user.balanceSpent -= chargeMMK;
      user.totalOrders  -= 1;
      await user.save({ session });

      order.status        = "Failed";
      order.providerError = providerRes.error;
      await order.save({ session });

      await session.commitTransaction();
      session.endSession();
      return res.status(400).json({ message: "Provider error: " + providerRes.error });
    }

    order.providerOrderId = providerRes.orderID;
    order.status          = "Pending";
    await order.save({ session });

    await session.commitTransaction();
    session.endSession();

    console.log("[ORDER] created", order._id, "→ provider", providerRes.orderID);
    res.status(201).json({
      message:          "Order placed successfully",
      orderId:          order._id,
      providerOrderId:  providerRes.orderID,
      remainingBalance: user.balance,
      order: {
        id:          order._id,
        serviceId,
        serviceName,
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
 * Returns current user's orders (newest first).
 * Query: ?page=1&limit=20&status=Pending
 */
app.get("/api/orders", guard, async (req, res) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page)  || 1);
    const limit  = Math.min(50, parseInt(req.query.limit) || 20);
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
 * Single order detail.
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
 * Fetch latest status from Brother SMM and update DB.
 */
app.post("/api/orders/:id/sync-status", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId)
      return res.status(400).json({ message: "No provider order ID for this order" });

    const data = await brotherAPI({
      actionType: "status",
      orderID:    order.providerOrderId,
    });

    // Update local record
    order.status          = data.orderStatus  || order.status;
    order.startCount      = data.startCount   || order.startCount;
    order.remains         = parseFloat(data.remaining_amount) || 0;
    order.refundedAmount  = parseFloat(data.refunded_amount)  || 0;
    await order.save();

    res.json({ message: "Status synced", order, providerData: data });
  } catch (e) {
    console.error("[SYNC ERR]", e.message);
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/sync-bulk
 * Sync status for up to 100 orders at once.
 * Body: { orderIds: ["dbId1","dbId2",...] }
 */
app.post("/api/orders/sync-bulk", guard, async (req, res) => {
  try {
    const { orderIds } = req.body;
    if (!Array.isArray(orderIds) || orderIds.length === 0)
      return res.status(400).json({ message: "orderIds array required" });
    if (orderIds.length > 100)
      return res.status(400).json({ message: "Maximum 100 orders per request" });

    const orders = await Order.find({ _id: { $in: orderIds }, user: req.uid });
    const providerIds = orders.map(o => o.providerOrderId).filter(Boolean);
    if (!providerIds.length)
      return res.json({ message: "No provider IDs found", updated: 0 });

    const data = await brotherAPI({
      actionType: "mass_status",
      orderID:    providerIds.join(","),
    });

    let updated = 0;
    for (const order of orders) {
      const d = data[order.providerOrderId];
      if (!d) continue;
      order.status         = d.orderStatus          || order.status;
      order.startCount     = d.startCount           || order.startCount;
      order.remains        = parseFloat(d.remaining_amount) || 0;
      order.refundedAmount = parseFloat(d.refunded_amount)  || 0;
      await order.save();
      updated++;
    }

    res.json({ message: `${updated} orders updated`, updated });
  } catch (e) {
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/:id/refill
 * Request a refill from Brother SMM.
 */
app.post("/api/orders/:id/refill", guard, async (req, res) => {
  try {
    const order = await Order.findOne({ _id: req.params.id, user: req.uid });
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.providerOrderId)
      return res.status(400).json({ message: "No provider order ID" });

    const data = await brotherAPI({
      actionType: "refill",
      orderID:    order.providerOrderId,
    });

    order.status = "Refill Requested";
    await order.save();

    res.json({ message: data.message || "Refill requested", providerResponse: data });
  } catch (e) {
    res.status(502).json({ message: e.message });
  }
});

/*
 * POST /api/orders/:id/cancel
 * Cancel order and request refund from provider.
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
      actionType: "cancel",
      orderID:    order.providerOrderId,
    });

    order.status = "Cancelled";
    await order.save();

    // Partial refund if remains > 0
    if (order.remains > 0) {
      const refundRatio = order.remains / order.quantity;
      const refundMMK   = Math.floor(order.chargeMMK * refundRatio);
      if (refundMMK > 0) {
        await User.findByIdAndUpdate(req.uid, {
          $inc: { balance: refundMMK, balanceSpent: -refundMMK },
        });
        return res.json({
          message:      data.message || "Order cancelled",
          refundMMK,
          providerResponse: data,
        });
      }
    }
    res.json({ message: data.message || "Order cancelled", providerResponse: data });
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
    app.listen(PORT, () => console.log(`🚀  Server running on port ${PORT}`));
  })
  .catch(e => {
    console.error("❌  MongoDB:", e.message);
    process.exit(1);
  });
