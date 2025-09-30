// server.js (CommonJS — ready to run)
const express = require("express");
const cors = require("cors");
const Razorpay = require("razorpay");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { Pool } = require("pg");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

/**
 * IMPORTANT:
 * - We use express.json() for normal JSON parsing.
 * - For webhook route we use express.raw({type: 'application/json'}) so we can
 *   compute HMAC over the exact raw body bytes for signature verification.
 */
app.use(cors());
app.use(express.json()); // for regular routes

// Postgres (Supabase) pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Supabase/Render
});

// Razorpay client
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Simple root
app.get("/", (req, res) => {
  res.send("🚀 SocialBond Backend is running (CommonJS)!");
});

/**
 * Create order endpoint
 * Expects JSON body: { amount: <number in INR>, currency?: "INR" }
 */
app.post("/create-order", async (req, res) => {
  try {
    const { amount, currency = "INR" } = req.body;
    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({ success: false, error: "Invalid amount" });
    }

    const options = {
      amount: Math.round(amount * 100), // paise
      currency,
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    return res.json({ success: true, order });
  } catch (err) {
    console.error("Error creating order:", err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * Webhook endpoint
 * Must use raw body and verify X-Razorpay-Signature (HMAC SHA256)
 */
app.post(
  "/webhook",
  // raw body parser for webhook route only
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
      const signature = req.headers["x-razorpay-signature"];

      if (!signature || !webhookSecret) {
        console.warn("Webhook missing signature or secret not set");
        return res.status(400).send("Missing signature or webhook secret");
      }

      const expected = crypto
        .createHmac("sha256", webhookSecret)
        .update(req.body)
        .digest("hex");

      if (signature !== expected) {
        console.warn("Invalid webhook signature", signature, expected);
        return res.status(400).send("Invalid signature");
      }

      // parse JSON safely from raw body
      const event = JSON.parse(req.body.toString());
      const paymentEntity = event.payload?.payment?.entity || null;

      // Save a compact record to DB (idempotent insert using event id unique)
      const query = `
        INSERT INTO payments (event_id, status, amount, currency, email, contact, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (event_id) DO NOTHING;
      `;

      await pool.query(query, [
        event.id,
        paymentEntity?.status || event.event || "unknown",
        paymentEntity?.amount || 0,
        paymentEntity?.currency || "INR",
        paymentEntity?.email || null,
        paymentEntity?.contact || null,
      ]);

      console.log("Stored webhook event:", event.id);
      return res.json({ status: "ok" });
    } catch (err) {
      console.error("Webhook handler error:", err);
      return res.status(500).send("Webhook error");
    }
  }
);

// Start server
app.listen(port, () => {
  console.log(`🚀 Server (CommonJS) running on port ${port}`);
});
