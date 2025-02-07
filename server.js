require("dotenv").config();
const express = require("express");
const multer = require("multer");
const mongoose = require("mongoose");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const passport = require("passport");
const bodyParser = require("body-parser");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
// const { text } = require("body-parser");

// Initialize Express app
const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "frontend")));
app.use("/imgs", express.static(path.join(__dirname, "imgs")));


app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login.html"));
});

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/location", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5000/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      // Here, you can store user info in the database if needed
      return done(null, profile);
    }
  )
);

// Serialize and Deserialize User
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google Auth Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "http://localhost:5000/login.html",
  }),
  (req, res) => {
    // Store user details in session
    req.session.user = req.user;

    // Redirect to frontend with user details
    res.redirect(
      `http://localhost:5000/home.html?email=${req.user.emails[0].value}&name=${req.user.displayName}`
    );
  }
);


// Logout route
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("http://localhost:5000/login.html");
  });
});


// Define the schema and model
const locationSchema = new mongoose.Schema({
  name: { type: String, required: true }, // Store user's full name
  email: { type: String, required: true },
  district: { type: String, required: true },
  roadName: { type: String, required: true },
  location: { type: String, required: true },
  problem: { type: String, required: true },
  surroundingProblems: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  imagePath: { type: String, required: true },
  category: {
    type: String,
    enum: ["Accident", "RoadIssue", "Other"],
    required: true,
  },
  votes: { type: Number, default: 0 }, // Add votes field
});

const Location = mongoose.model("Location", locationSchema);

// Haversine formula for distance calculation
const haversineDistance = (lat1, lon1, lat2, lon2) => {
  const R = 6371; // Earth radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)) * 1000; // Distance in meters
};

// Multer configuration for file uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    },
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"));
    }
  },
});

// User Schema and Model
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone_number: { type: String, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);


// Route: Sign Up
app.post("/signup", async (req, res) => {
  const { full_name, email, phone_number, password } = req.body;

  if (!full_name || !email || !phone_number || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      full_name,
      email,
      phone_number,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({
      message: "User registered successfully",
      user: { full_name: newUser.full_name, email: newUser.email },
    });
  } catch (err) {
    console.error("Error during sign-up:", err);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    res.status(200).json({
      message: "Login successful",
      user: { full_name: user.full_name, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "An error occurred during login" });
  }
});

// Route to add location details
app.post("/location", upload.single("image"), async (req, res) => {
  try {
    let {
      name,
      email,
      district,
      roadName,
      location,
      problem,
      surroundingProblems,
      category,
    } = req.body;
    const imagePath = req.file ? req.file.filename : null;

    // Ensure email is a string (take the first email if it's an array)
    if (Array.isArray(email)) {
      email = email[0]; // Take the first email in the array
    }

    if (!email) return res.status(400).json({ error: "User email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const [latitude, longitude] = location.split(",").map(Number);
    if (isNaN(latitude) || isNaN(longitude)) {
      return res.status(400).json({ error: "Invalid location coordinates" });
    }

    const newLocation = new Location({
      name: user.full_name,
      email, // Now email is a valid string
      district,
      roadName,
      location,
      problem,
      surroundingProblems,
      latitude,
      longitude,
      imagePath,
      category,
    });

    const mailOptions = {
      from: `"Support Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Report Submission Confirmation",
      text:`Hello,\n\nYour report has been successfully submitted on ${new Date().toLocaleString()}.\n\nDetails:\nDistrict: ${district}\nRoad Name: ${roadName}\nProblem: ${problem}\n\nThank you for your contribution!`,
    };


    await newLocation.save();
    await transporter.sendMail(mailOptions);
    await User.updateOne({ email }, { $inc: { postCount: 1 } });

    res.json({ message: "Location saved successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message || "Error saving location" });
  }
});



// Route to fetch all locations
app.get("/locations", async (req, res) => {
  try {
    const locations = await Location.find({});
    res.status(200).json(locations);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/locations", async (req, res) => {
  try {
    const locations = await Location.find().populate("userId", "name email");
    res.json(locations);
  } catch (error) {
    res.status(500).json({ message: "Error fetching locations", error });
  }
});


// Route to vote on a location
app.patch("/locations/:id/vote", async (req, res) => {
  const { id } = req.params;

  try {
    const location = await Location.findById(id);
    if (!location) {
      return res.status(404).json({ error: "Location not found" });
    }

    location.votes += 1;
    await location.save();

    res
      .status(200)
      .json({ message: "Vote added successfully", votes: location.votes });
  } catch (error) {
    console.error("Error adding vote:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Route to delete a location
app.delete("/locations/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const deletedLocation = await Location.findByIdAndDelete(id);
    if (deletedLocation) {
      res.status(200).json({ message: "Location deleted successfully." });
    } else {
      res.status(404).json({ error: "Location not found." });
    }
  } catch (error) {
    console.error("Error deleting location:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Admin Login Route
app.post("/admin-login", (req, res) => {
  const { email, password } = req.body;

  if (email === "skirubakaran2005@gmail.com" && password === "1406") {
    res.json({ message: "Login successful" });
  } else {
    res.status(400).json({ error: "Invalid credentials" });
  }
});

// Serve static files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.get("/profile/:email", async (req, res) => {
  try {
    const email = req.params.email.toLowerCase(); // Ensure case-insensitive match
    const user = await User.findOne({ email });

    if (user) {
      res.json({
        full_name: user.full_name,
        email: user.email,
        phone_number: user.phone_number,
      });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Fetch user report stats
app.get("/user-reports/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ postCount: user.postCount, completedCount: user.completedCount });
  } catch (error) {
    res.status(500).json({ error: "Error fetching user report stats" });
  }
});

// Fetch all reports
app.get("/locations", async (req, res) => {
  try {
    const reports = await Report.find({ status: "pending" });
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: "Error fetching reports" });
  }
});


app.get("/users/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ name: user.name, email: user.email });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, 
  },
});

// API to mark a location as completed
app.patch("/locations/:id/complete", async (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  try {
    const location = await Location.findById(id);
    if (!location) {
      return res.status(404).json({ error: "Location not found" });
    }

    // Send Email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Issue Resolved",
      text: `Hello, \n\nThe reported issue at ${location.roadName}, ${location.district} has been resolved. \n\nThank you for your contribution!`,
    };

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).json({ error: "Failed to send email" });
      }

      // Delete from database after email is sent
      await Location.findByIdAndDelete(id);
      res
        .status(200)
        .json({ message: "Location marked as completed and deleted." });
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});








// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});



