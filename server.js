// server.js

// 1. Core Module Imports
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import nodemailer from 'nodemailer';
import sgMail from '@sendgrid/mail'; // Added SendGrid import

// 2. Load Environment Variables
dotenv.config();

// 3. Initialize Express App
const app = express();

// 4. Middleware Setup
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));

const limiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: { error: 'Too many requests, please try again later.' } 
});
app.use('/api/', limiter);

const loginLimiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: 'Too many login attempts, please try again later.' } 
});

// 5. Passport.js Session Management
app.use(session({ 
  secret: process.env.SESSION_SECRET, 
  resave: false, 
  saveUninitialized: true 
}));
app.use(passport.initialize());
app.use(passport.session());

// 6. Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Connection error:'));
db.once('open', () => console.log('✅ Connected to MongoDB'));

// 7. Mongoose User Schema
const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true, 
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email'] 
  },
  password: { 
    type: String, 
    minlength: 6 
  },
  name: { 
    type: String, 
    required: true, 
    trim: true 
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  loginAttempts: { 
    type: Number, 
    default: 0 
  },
  lockUntil: Date,
  refreshToken: String,
  googleId: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  githubId: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  provider: { 
    type: String, 
    enum: ['local', 'google', 'github'], 
    default: 'local' 
  },
  otp: {
    type: String,
    default: null
  },
  otpExpires: {
    type: Date,
    default: null
  }
}, { 
  timestamps: true 
});

userSchema.virtual('isLocked').get(function() { 
  return !!(this.lockUntil && this.lockUntil > Date.now()); 
});

userSchema.pre('save', async function(next) { 
  if (!this.isModified('password')) return next(); 
  try { 
    const salt = await bcrypt.genSalt(12); 
    this.password = await bcrypt.hash(this.password, salt); 
    next(); 
  } catch (error) { 
    next(error); 
  } 
});

userSchema.methods.comparePassword = async function(candidatePassword) { 
  if (this.isLocked) throw new Error('Account is temporarily locked due to too many failed login attempts'); 
  const isMatch = await bcrypt.compare(candidatePassword, this.password); 
  if (isMatch) { 
    if (this.loginAttempts > 0) { 
      this.loginAttempts = 0; 
      this.lockUntil = undefined; 
      await this.save(); 
    } 
    return true; 
  } else { 
    this.loginAttempts += 1; 
    if (this.loginAttempts >= 5) { 
      this.lockUntil = Date.now() + (30 * 60 * 1000); 
    } 
    await this.save(); 
    return false; 
  } 
};

userSchema.methods.generateTokens = function() { 
  const accessToken = jwt.sign({ 
    userId: this._id, 
    email: this.email, 
    name: this.name 
  }, process.env.JWT_SECRET, { 
    expiresIn: '15m' 
  }); 
  
  const refreshToken = jwt.sign({ 
    userId: this._id 
  }, process.env.JWT_REFRESH_SECRET, { 
    expiresIn: '7d' 
  }); 
  
  return { accessToken, refreshToken }; 
};

const User = mongoose.model('User', userSchema);

// ------------------ QUIZ HISTORY SCHEMA (UPDATED) ------------------
const quizHistorySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "User", 
    required: true 
  },
  topic: { 
    type: String, 
    required: true, 
    enum: [ 
      'Logical Reasoning', 
      'Coding & Problem-Solving', 
      'Quantitative Aptitude', 
      'CS Fundamentals', 
      'Verbal & Communication', 
      'Mock Tests & Assessments' 
    ] 
  },
  score: { 
    type: Number, 
    required: true 
  },
  totalQuestions: { 
    type: Number, 
    required: true 
  },
  percentage: { 
    type: Number 
  },
  correctAnswers: { 
    type: Number 
  },
  incorrectAnswers: { 
    type: Number 
  },
  dateTaken: { 
    type: Date, 
    default: Date.now 
  }
}, { 
  timestamps: true 
});

quizHistorySchema.pre('save', function(next) {
  if (this.isNew) {
    this.percentage = Math.round((this.score / this.totalQuestions) * 100);
    this.correctAnswers = this.score;
    this.incorrectAnswers = this.totalQuestions - this.score;
  }
  next();
});

const QuizHistory = mongoose.model("QuizHistory", quizHistorySchema);
// -------------------------------------------------------------------

// 8. SendGrid Email Transporter
const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  auth: {
    user: "apikey", // fixed value
    pass: process.env.SENDGRID_API_KEY, // stored in .env file
  },
});

// Set up SendGrid API key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Email sending function
const sendEmail = async (to, subject, html) => {
  const mailOptions = {
    from: process.env.EMAIL_FROM || "quizzhaala@example.com", // Should be a verified sender in SendGrid
    to,
    subject,
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('✅ Email sent successfully to:', to);
    return true;
  } catch (err) {
    console.error('❌ Email sending error:', err);
    throw new Error('Failed to send email');
  }
};

// OTP Email function
const sendOtpEmail = async (email, name) => {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes
  
  // Update user with new OTP
  await User.findOneAndUpdate(
    { email },
    { otp, otpExpires }
  );
  
  try {
    await sendEmail(
      email,
      "Quizshaala Email Verification",
      `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
          <p>Hello ${name},</p>
          <p>Thank you for registering with Quizshaala. Please use the following OTP to verify your email address:</p>
          <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
            <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #4F46E5;">${otp}</span>
          </div>
          <p>This OTP will expire in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <br>
          <p>Best regards,<br>Quizshaala Team</p>
        </div>
      `
    );
    
    return true;
  } catch (emailError) {
    console.error('Email sending error:', emailError);
    throw new Error('Failed to send verification email');
  }
};

// 9. Passport.js Strategies
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google Strategy (Single implementation - no duplicates)
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (user) {
      if (!user.isVerified) {
        await sendOtpEmail(user.email, user.name); // resend OTP if not verified
      }
      return done(null, user);
      } else {
        user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
          user.googleId = profile.id;
          user.isVerified = false; // OTP required
          user.provider = 'google';
          await user.save();
        } else {
          user = new User({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            isVerified: false, // OTP required
            provider: 'google',
            password: 'temp-password'
          });
          await user.save();
        }

        // Send OTP via SendGrid
        await sendOtpEmail(user.email, user.name);

        return done(null, user);
      }
    } catch (err) {
      return done(err, null);
    }
  }
));

// GitHub Strategy (Fixed to require OTP verification)
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/auth/github/callback`,
    scope: ['user:email']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ githubId: profile.id });
        if (user) {
        if (!user.isVerified) {
       await sendOtpEmail(user.email, user.name); // resend OTP if not verified
      }
      return done(null, user);
      } else {
        const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
        user = await User.findOne({ email });
        if (user) {
          user.githubId = profile.id;
          user.isVerified = false; // OTP required
          user.provider = 'github';
          await user.save();
        } else {
          user = new User({
            githubId: profile.id,
            name: profile.displayName || profile.username,
            email: email,
            isVerified: false, // OTP required
            provider: 'github',
            password: 'temp-password'
          });
          await user.save();
        }

        // Send OTP via SendGrid
        await sendOtpEmail(user.email, user.name);

        return done(null, user);
      }
    } catch (err) {
      return done(err, null);
    }
  }
));

// 10. API Routes
const router = express.Router();

// Health check
app.get('/api/health', (req, res) => res.json({ 
  status: 'Server is running', 
  timestamp: new Date().toISOString() 
}));

// Send email endpoint (for testing)
app.post("/send-email", async (req, res) => {
  const { to, subject, text } = req.body;

  try {
    await sendEmail(to, subject, text);
    res.json({ success: true, message: "✅ Email sent successfully!" });
  } catch (err) {
    console.error("❌ Email sending error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Contact form endpoint using SendGrid
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;

  const msg = {
    to: 'your-email@example.com', // where you want to receive messages
    from: 'no-reply@quizshaala.com', // must be verified in SendGrid
    subject: `New Contact Form Submission from ${name}`,
    text: message,
    html: `<p><strong>Name:</strong> ${name}</p>
           <p><strong>Email:</strong> ${email}</p>
           <p><strong>Message:</strong> ${message}</p>`
  };

  try {
    await sgMail.send(msg);
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Email failed', error });
  }
});

// OTP Signup
router.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    
    const existingUser = await User.findOne({ email });

if (existingUser) {
  if (!existingUser.isVerified) {
    // User exists but NOT verified → resend OTP instead of blocking
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    existingUser.otp = otp;
    existingUser.otpExpires = otpExpires;
    await existingUser.save();

    await sendEmail(
      email,
      "Quizshaala Email Verification",
      `
        <p>Hello ${existingUser.name},</p>
        <p>Your OTP is: <strong>${otp}</strong></p>
        <p>This OTP will expire in 10 minutes.</p>
      `
    );

    return res.status(200).json({
      message: 'Email already exists but not verified. OTP resent.',
      userId: existingUser._id
    });
  }

  // Already verified → block signup
  return res.status(400).json({ error: 'User with this email already exists' });
}

    
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes
    
    // Hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user with OTP (not verified yet)
    const user = new User({ 
      email, 
      password: hashedPassword, 
      name,
      otp,
      otpExpires,
      isVerified: false
    });
    
    await user.save();

    // Send OTP email using SendGrid
    try {
      await sendEmail(
        email,
        "Quizshaala Email Verification",
        `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
            <p>Hello ${name},</p>
            <p>Thank you for registering with Quizshaala. Please use the following OTP to verify your email address:</p>
            <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
              <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #4F46E5;">${otp}</span>
            </div>
            <p>This OTP will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <br>
            <p>Best regards,<br>Quizshaala Team</p>
          </div>
        `
      );
      
      res.status(201).json({
        message: 'OTP sent to email. Please verify to complete registration.',
        userId: user._id
      });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      // Delete the user if email fails
      await User.findByIdAndDelete(user._id);
      return res.status(500).json({ error: 'Failed to send verification email' });
    }
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if OTP matches and is not expired
    if (user.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    
    if (user.otpExpires < new Date()) {
      return res.status(400).json({ error: 'OTP has expired' });
    }
    
    // ✅ Reset lock and login attempts
    user.isVerified = true;
    user.otp = null;
    user.otpExpires = null;
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    
    // Generate tokens
    const { accessToken, refreshToken } = user.generateTokens();
    user.refreshToken = refreshToken;
    await user.save();
    
    res.json({
      message: 'Email verified successfully. Registration complete!',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Resend OTP
router.post('/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.isVerified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    // ✅ Reset lock if user is currently locked
    if (user.isLocked) {
      user.loginAttempts = 0;
      user.lockUntil = null;
    }
    
    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes
    
    // Update user with new OTP
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();
    
    // Send new OTP email using SendGrid
    try {
      await sendEmail(
        email,
        "Quizshaala New Verification OTP",
        `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
            <p>Hello ${user.name},</p>
            <p>Here is your new verification OTP:</p>
            <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
              <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: '4F46E5';">${otp}</span>
            </div>
            <p>This OTP will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <br>
            <p>Best regards,<br>Quizshaala Team</p>
          </div>
        `
      );
      
      res.json({ message: 'New OTP sent to your email' });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      return res.status(500).json({ error: 'Failed to send OTP email' });
    }
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Local Login (updated to check verification status)
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Check if user is verified
    if (!user.isVerified) {
      return res.status(401).json({ error: 'Please verify your email before logging in' });
    }
    
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const { accessToken, refreshToken } = user.generateTokens();
    user.refreshToken = refreshToken;
    await user.save();
    
    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Login error:', error);
    if (error.message.includes('Account is temporarily locked')) {
      return res.status(423).json({ error: error.message });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh token route
router.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    const { accessToken, refreshToken: newRefreshToken } = user.generateTokens();
    user.refreshToken = newRefreshToken;
    await user.save();
    res.json({
      accessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Logout route (protected)
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.userId, { refreshToken: null });
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ------------------ QUIZ HISTORY ROUTES ------------------
router.post("/history", authenticateToken, async (req, res) => {
  try {
    const { topic, score, totalQuestions } = req.body;
    if (!topic || score == null || totalQuestions == null) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const history = new QuizHistory({ 
      userId: req.user.userId, 
      topic, 
      score, 
      totalQuestions 
    });
    await history.save();
    res.status(201).json({ message: "History saved", history });
  } catch (error) { 
    console.error("Save history error:", error); 
    res.status(500).json({ error: "Failed to save history" }); 
  }
});

router.get("/history", authenticateToken, async (req, res) => {
  try { 
    const history = await QuizHistory.find({ userId: req.user.userId }).sort({ dateTaken: -1 }); 
    res.json(history); 
  } catch (error) { 
    console.error("Fetch history error:", error); 
    res.status(500).json({ error: 'Failed to fetch history' }); 
  }
});
// ----------------------------------------------------------

// ------------------ LEADERBOARD ROUTE ------------------
router.get("/leaderboard/:topic", async (req, res) => {
  const { topic } = req.params;
  const validTopics = [ 
    'Logical Reasoning', 
    'Coding & Problem-Solving', 
    'Quantitative Aptitude', 
    'CS Fundamentals', 
    'Verbal & Communication', 
    'Mock Tests & Assessments' 
  ];
  if (!validTopics.includes(topic)) return res.status(400).json({ error: "Invalid topic" });
  try {
    const leaderboard = await QuizHistory.aggregate([
      { $match: { topic } },
      { $lookup: { from: "users", localField: "userId", foreignField: "_id", as: "user" } },
      { $unwind: "$user" },
      { $project: { _id: 1, score: 1, totalQuestions: 1, percentage: 1, dateTaken: 1, username: "$user.name" } },
      { $sort: { score: -1, percentage: -1, dateTaken: 1 } },
      { $limit: 50 }
    ]);
    res.json(leaderboard);
  } catch (error) { 
    console.error("Leaderboard error:", error); 
    res.status(500).json({ error: "Failed to load leaderboard" }); 
  }
});
// ----------------------------------------------------------

// ------------------ DASHBOARD SUMMARY ROUTE ------------------
router.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const history = await QuizHistory.find({ userId });
    if (history.length === 0) return res.json({ 
      totalQuizzes: 0, 
      bestScore: 0, 
      averageScore: 0, 
      topics: [], 
      completionRate: 0 
    });

    const totalQuizzes = history.length;
    const bestScore = Math.max(...history.map(h => h.score));
    const totalPossible = history.reduce((sum, h) => sum + h.totalQuestions, 0);
    const totalCorrect = history.reduce((sum, h) => sum + h.score, 0);
    const averageScore = Math.round((totalCorrect / totalPossible) * 100);
    const topics = [...new Set(history.map(h => h.topic))];
    const badges = [];
    if (bestScore >= 45) badges.push("Quiz Master");
    if (averageScore >= 80) badges.push("Top Performer");
    if (totalQuizzes >= 10) badges.push("Marathon Learner");

    res.json({ 
      totalQuizzes, 
      bestScore, 
      averageScore, 
      topics, 
      badges, 
      lastActivity: history[0]?.dateTaken 
    });
  } catch (error) { 
    console.error("Dashboard error:", error); 
    res.status(500).json({ error: "Failed to load dashboard" }); 
  }
});
// ----------------------------------------------------------

// Get user profile (protected route)
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -refreshToken');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        provider: user.provider,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { name },
      { new: true }
    ).select('-password -refreshToken');
    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password
router.put('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: process.env.FRONTEND_URL + '/login' }),
  (req, res) => {
    const user = req.user;
    // For OAuth users, redirect to OTP verification page instead of auto-login
    res.redirect(`${process.env.FRONTEND_URL}/verify-oauth?email=${user.email}&provider=${user.provider}`);
  }
);

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: process.env.FRONTEND_URL + '/login' }),
  (req, res) => {
    const user = req.user;
    // For OAuth users, redirect to OTP verification page instead of auto-login
    res.redirect(`${process.env.FRONTEND_URL}/verify-oauth?email=${user.email}&provider=${user.provider}`);
  }
);

// OAuth OTP verification endpoint
router.post('/verify-oauth-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if OTP matches and is not expired
    if (user.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    
    if (user.otpExpires < new Date()) {
      return res.status(400).json({ error: 'OTP has expired' });
    }
    
    // ✅ Reset lock and login attempts
    user.isVerified = true;
    user.otp = null;
    user.otpExpires = null;
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    
    // Generate tokens
    const { accessToken, refreshToken } = user.generateTokens();
    user.refreshToken = refreshToken;
    await user.save();
    
    res.json({
      message: 'Email verified successfully. Registration complete!',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified,
        provider: user.provider
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('OAuth OTP verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Final route setup
app.use('/api', router);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Server Start
const PORT = process.env.PORT || 1;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

export default app;