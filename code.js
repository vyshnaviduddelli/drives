const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const WebSocket = require("ws");

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = "your_jwt_secret";
const MONGO_URI = "mongodb://localhost:27017/jobPortal";

// Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("Error: ", err));

// Schemas and Models
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const JobSchema = new mongoose.Schema({
  title: String,
  description: String,
  postedBy: String,
  applicants: [String],
});

const User = mongoose.model("User", UserSchema);
const Job = mongoose.model("Job", JobSchema);

// Rate Limiting Middleware
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
});
app.use(apiLimiter);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const verified = jwt.verify(token.split(" ")[1], JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid Token" });
  }
};

// Routes
// 1. Register
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 2. Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Post a Job
app.post("/jobs", authenticateToken, async (req, res) => {
  const { title, description } = req.body;

  try {
    const job = new Job({ title, description, postedBy: req.user.id });
    await job.save();
    res.status(201).json({ message: "Job posted successfully" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4. Get Job Listings
app.get("/jobs", async (req, res) => {
  try {
    const jobs = await Job.find();
    res.json(jobs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Apply for a Job
app.post("/jobs/:id/apply", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ message: "Job not found" });

    job.applicants.push(req.user.id);
    await job.save();
    res.json({ message: "Applied successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// WebSocket for Real-time Updates
const wss = new WebSocket.Server({ port: 8080 });
wss.on("connection", (ws) => {
  console.log("Client connected");

  ws.on("message", (message) => {
    console.log("Received: ", message);
  });

  // Send real-time updates
  setInterval(() => {
    ws.send(JSON.stringify({ type: "update", message: "New job posted!" }));
  }, 10000);

  ws.on("close", () => console.log("Client disconnected"));
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
