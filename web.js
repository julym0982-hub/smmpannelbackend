// ════════════════════════════════════════════════════════════════
//  web.js  —  SMM Panel Backend (Single File)
//  Stack  : Node.js + Express + MongoDB (Mongoose) + JWT + bcrypt
//  Host   : Render.com
// ════════════════════════════════════════════════════════════════

"use strict";

require("dotenv").config();
const express    = require("express");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");

// ──────────────────────────────────────────────────────────────
//  ENV & CONSTANTS
// ──────────────────────────────────────────────────────────────
const PORT         = process.env.PORT         || 5000;
const MONGODB_URI  = process.env.MONGODB_URI;
const JWT_SECRET   = process.env.JWT_SECRET   || "change_me_in_env";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const JWT_EXPIRES  = "7d";
const SALT_ROUNDS  = 12;

if (!MONGODB_URI) {
  console.error("❌  MONGODB_URI is not set in .env");
  process.exit(1);
}

// ──────────────────────────────────────────────────────────────
//  EXPRESS APP
// ──────────────────────────────────────────────────────────────
const app = express();

// ── CORS ──────────────────────────────────────────────────────
const allowedOrigins = [
  FRONTEND_URL,
  "http://localhost:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://127.0.0.1:3000",
];

app.use(
  cors({
    origin(origin, cb) {
      // Allow requests with no origin (Postman, curl, etc.)
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error(`CORS blocked: ${origin}`));
    },
    credentials:    true,
    methods:        ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// ──────────────────────────────────────────────────────────────
//  MONGOOSE — USER MODEL
// ──────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    name: {
      type:     String,
      required: [true, "Name is required"],
      trim:     true,
    },
    email: {
      type:     String,
      required: [true, "Email is required"],
      unique:   true,
      lowercase: true,
      trim:     true,
      match:    [/^\S+@\S+\.\S+$/, "Invalid email format"],
    },
    password: {
      type:      String,
      required:  [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
    },
    balance:      { type: Number, default: 0 },
    balanceSpent: { type: Number, default: 0 },
    totalOrders:  { type: Number, default: 0 },
  },
  { timestamps: true }
);

// Auto-hash password before save
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
  next();
});

// Compare plaintext vs hashed
userSchema.methods.matchPassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

const User = mongoose.model("User", userSchema);

// ──────────────────────────────────────────────────────────────
//  HELPERS
// ──────────────────────────────────────────────────────────────

/** Sign and return a JWT */
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

/** Safe user object to return (no password) */
function safeUser(user) {
  return {
    id:           user._id,
    name:         user.name,
    email:        user.email,
    balance:      user.balance,
    balanceSpent: user.balanceSpent,
    totalOrders:  user.totalOrders,
  };
}

// ──────────────────────────────────────────────────────────────
//  MIDDLEWARE — JWT Auth Guard
// ──────────────────────────────────────────────────────────────
function authGuard(req, res, next) {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: "Not authorized — token missing" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Not authorized — invalid token" });
  }
}

// ──────────────────────────────────────────────────────────────
//  ROUTES
// ──────────────────────────────────────────────────────────────

// ── Health check ──────────────────────────────────────────────
app.get("/", (_req, res) => {
  res.json({ status: "🚀 SMM Panel API is running", time: new Date() });
});

// ── POST /api/auth/signup ─────────────────────────────────────
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Please fill in all fields" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    // Duplicate check
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ message: "Email is already registered" });
    }

    // Create user (password hashed by pre-save hook)
    const user = await User.create({ name, email, password });

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

// ── POST /api/auth/login ──────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Please fill in all fields" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const matched = await user.matchPassword(password);
    if (!matched) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

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

// ── POST /api/auth/reset-password ────────────────────────────
//  Direct reset: user provides email + new password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ message: "Email and new password are required" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: "New password must be at least 6 characters" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "No account found with this email" });
    }

    // Hash new password manually (bypassing pre-save for clarity)
    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await user.save({ validateBeforeSave: false });

    return res.json({ message: "Password reset successfully. You can now log in." });
  } catch (err) {
    console.error("Reset-password error:", err.message);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── GET /api/auth/me  (Protected) ────────────────────────────
app.get("/api/auth/me", authGuard, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.json(safeUser(user));
  } catch (err) {
    console.error("Me error:", err.message);
    return res.status(500).json({ message: "Server error" });
  }
});

// ──────────────────────────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ──────────────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ message: err.message || "Internal server error" });
});

// ──────────────────────────────────────────────────────────────
//  DATABASE CONNECTION → START SERVER
// ──────────────────────────────────────────────────────────────
mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log("✅  MongoDB connected");
    app.listen(PORT, () => {
      console.log(`🚀  Server listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌  MongoDB connection failed:", err.message);
    process.exit(1);
  });
