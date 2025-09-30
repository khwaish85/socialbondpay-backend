import express from "express";
import cors from "cors";
import Razorpay from "razorpay";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import crypto from "crypto";   // ✅ for webhook signature validation
import pkg from "pg";

dotenv.config();

const { Pool } = pkg;
const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(bodyParser.json());

// PostgreSQL connection (Supabase)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ✅ Create Order API
app.post("/create-order", async (req, res) => {
  try {
    const { amount, currency = "INR" } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, error: "Invalid amount" });
    }

    const options = {
      amount: amount * 100, // paise
      currency,
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);

    res.json({ success: true, order });
  } catch (error) {
    console.error("❌ Error creating order:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ✅ Razorpay Webhook (store payment history)
app.post("/webhook", async (req, res) => {
  try {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

    const signature = req.headers["x-razorpay-signature"];
    const body = JSON.stringify(req.body);

    // Verify signature
    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex");

    if (signature !== expectedSignature) {
      return res.status(400).send("Invalid signature");
    }

    const event = req.body;
    const paymentEntity = event.payload?.payment?.entity;

    // Save into DB
    const query = `
      INSERT INTO payments (event_id, status, amount, currency, email, contact, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      ON CONFLICT (event_id) DO NOTHING;
    `;

    await pool.query(query, [
      event.id,
      paymentEntity?.status || "created",
      paymentEntity?.amount || 0,
      paymentEntity?.currency || "INR",
      paymentEntity?.email || null,
      paymentEntity?.contact || null,
    ]);

    console.log("✅ Payment event stored:", event.id);
    res.json({ status: "ok" });
  } catch (error) {
    console.error("❌ Webhook error:", error);
    res.status(500).send("Webhook error");
  }
});

// ✅ Test route
app.get("/", (req, res) => {
  res.send("🚀 SocialBond Backend is running!");
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
