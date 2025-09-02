// server.js - Enhanced Version

// 1. Core Module Imports
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import session from 'express-session';
import nodemailer from 'nodemailer';
import sgMail from '@sendgrid/mail';
import helmet from 'helmet'; // Added for security headers
import { body, validationResult } from 'express-validator'; // Added for input validation

// 2. Load Environment Variables
dotenv.config();

// 3. Initialize Express App
const app = express();

// 4. Enhanced Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL 
    : 'http://localhost:3000',
  credentials: true
}));

// 5. Session Management
console.log("SESSION_SECRET =", process.env.SESSION_SECRET ? "Set" : "Not Set");

app.use(session({ 
  secret: process.env.SESSION_SECRET, 
  resave: false, 
  saveUninitialized: false, // Changed to false for security
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

// 6. Database Connection with enhanced settings
mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// 7. Enhanced Rate Limiting
const generalLimiter = rateLimit({ 
  windowMs: 15 * 60 * 1000,
  max: 100, 
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({ 
  windowMs: 15 * 60 * 1000,
  max: 5, 
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Too many OTP requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', generalLimiter);

// 8. Mongoose User Schema with enhanced security
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
    minlength: 6,
    required: true,
    select: false // Don't include password in queries by default
  },
  name: { 
    type: String, 
    required: true, 
    trim: true,
    maxlength: 50
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  loginAttempts: { 
    type: Number, 
    default: 0,
    select: false
  },
  lockUntil: {
    type: Date,
    select: false
  },
  refreshToken: {
    type: String,
    select: false
  },
  otp: {
    type: String,
    select: false,
    default: null
  },
  otpExpires: {
    type: Date,
    select: false,
    default: null
  }
}, { 
  timestamps: true 
});

// Index for better performance
userSchema.index({ email: 1 });
userSchema.index({ isVerified: 1 });

userSchema.virtual('isLocked').get(function() { 
  return !!(this.lockUntil && this.lockUntil > Date.now()); 
});

userSchema.methods.resetLock = function() {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  return this.save();
};

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
  if (this.isLocked) {
    throw new Error('Account is temporarily locked due to too many failed login attempts. Try again in 30 minutes.');
  }
  
  const isMatch = await bcrypt.compare(candidatePassword, this.password); 
  if (isMatch) { 
    if (this.loginAttempts > 0) { 
      await this.resetLock();
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
    expiresIn: '15m',
    issuer: 'quizshaala-api',
    audience: 'quizshaala-users'
  }); 
  
  const refreshToken = jwt.sign({ 
    userId: this._id 
  }, process.env.JWT_REFRESH_SECRET, { 
    expiresIn: '7d',
    issuer: 'quizshaala-api',
    audience: 'quizshaala-users'
  }); 
  
  return { accessToken, refreshToken }; 
};

const User = mongoose.model('User', userSchema);

// Quiz History Schema with indexing
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
    required: true,
    min: 0
  },
  totalQuestions: { 
    type: Number, 
    required: true,
    min: 1
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

// Index for better performance
quizHistorySchema.index({ userId: 1, dateTaken: -1 });
quizHistorySchema.index({ topic: 1, score: -1 });

quizHistorySchema.pre('save', function(next) {
  if (this.isNew || this.isModified('score') || this.isModified('totalQuestions')) {
    this.percentage = Math.round((this.score / this.totalQuestions) * 100);
    this.correctAnswers = this.score;
    this.incorrectAnswers = this.totalQuestions - this.score;
  }
  next();
});

const QuizHistory = mongoose.model("QuizHistory", quizHistorySchema);

// 9. Enhanced Email Setup with better error handling
const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  auth: {
    user: "apikey",
    pass: process.env.SENDGRID_API_KEY,
  },
});

// Set up SendGrid API key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Enhanced email sending function with retry logic
const sendEmail = async (to, subject, html, retries = 3) => {
  const mailOptions = {
    from: process.env.EMAIL_FROM || "noreply@quizshaala.com",
    to,
    subject,
    html,
  };

  for (let i = 0; i < retries; i++) {
    try {
      await transporter.sendMail(mailOptions);
      console.log('✅ Email sent successfully to:', to);
      return true;
    } catch (err) {
      console.error(`❌ Email sending attempt ${i + 1} failed:`, err);
      if (i === retries - 1) throw new Error('Failed to send email after multiple attempts');
      // Wait before retrying (exponential backoff would be better)
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
    }
  }
};

// OTP Email function
const sendOtpEmail = async (email, name, otp) => {
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

// 10. Validation middleware
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    res.status(400).json({ 
      error: 'Validation failed', 
      details: errors.array() 
    });
  };
};

// 11. API Routes
const router = express.Router();

// Health check
app.get('/api/health', (req, res) => res.json({ 
  status: 'Server is running', 
  timestamp: new Date().toISOString(),
  uptime: process.uptime()
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
app.post('/api/contact', [
  body('name').trim().isLength({ min: 1 }).withMessage('Name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('message').trim().isLength({ min: 10 }).withMessage('Message must be at least 10 characters')
], validate, async (req, res) => {
  const { name, email, message } = req.body;

  const msg = {
    to: process.env.CONTACT_EMAIL || 'your-email@example.com',
    from: process.env.EMAIL_FROM || 'no-reply@quizshaala.com',
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
    res.status(500).json({ message: 'Email failed', error: error.message });
  }
});

// OTP Signup with validation
router.post('/signup', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('name').trim().isLength({ min: 1, max: 50 }).withMessage('Name must be between 1-50 characters')
], validate, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      if (!existingUser.isVerified) {
        // User exists but NOT verified → resend OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        existingUser.otp = otp;
        existingUser.otpExpires = otpExpires;
        await existingUser.save();

        await sendOtpEmail(email, existingUser.name, otp);

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
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    
    // Create user with OTP (not verified yet)
    const user = new User({ 
      email, 
      password, 
      name,
      otp,
      otpExpires,
      isVerified: false
    });
    
    await user.save();

    // Send OTP email using SendGrid
    try {
      await sendOtpEmail(email, name, otp);
      
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

// Verify OTP with validation
router.post('/verify-otp', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], validate, async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    const user = await User.findOne({ email }).select('+otp +otpExpires');
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

// Resend OTP with rate limiting
router.post('/resend-otp', otpLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
], validate, async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.isVerified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    // ✅ Always reset login attempts when OTP is requested
    if (user.loginAttempts > 0 || user.isLocked) {
      await user.resetLock();
    }
    
    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    
    // Update user with new OTP
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();
    
    // Send new OTP email using SendGrid
    try {
      await sendOtpEmail(email, user.name, otp);
      
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

// Local Login with validation
router.post('/login', loginLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').exists().withMessage('Password is required')
], validate, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email }).select('+password +loginAttempts +lockUntil');
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
    
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, {
      issuer: 'quizshaala-api',
      audience: 'quizshaala-users'
    });
    
    const user = await User.findById(decoded.userId).select('+refreshToken');
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
  
  jwt.verify(token, process.env.JWT_SECRET, {
    issuer: 'quizshaala-api',
    audience: 'quizshaala-users'
  }, (err, user) => {
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

// Quiz History Routes with validation
router.post("/history", authenticateToken, [
  body('topic').isIn([
    'Logical Reasoning', 
    'Coding & Problem-Solving', 
    'Quantitative Aptitude', 
    'CS Fundamentals', 
    'Verbal & Communication', 
    'Mock Tests & Assessments'
  ]).withMessage('Valid topic is required'),
  body('score').isInt({ min: 0 }).withMessage('Valid score is required'),
  body('totalQuestions').isInt({ min: 1 }).withMessage('Valid total questions is required')
], validate, async (req, res) => {
  try {
    const { topic, score, totalQuestions } = req.body;
    
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const history = await QuizHistory.find({ userId: req.user.userId })
      .sort({ dateTaken: -1 })
      .skip(skip)
      .limit(limit);
      
    const total = await QuizHistory.countDocuments({ userId: req.user.userId });
    
    res.json({
      history,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }); 
  } catch (error) { 
    console.error("Fetch history error:", error); 
    res.status(500).json({ error: 'Failed to fetch history' }); 
  }
});

// Leaderboard Route
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
  
  if (!validTopics.includes(topic)) {
    return res.status(400).json({ error: "Invalid topic" });
  }
  
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const leaderboard = await QuizHistory.aggregate([
      { $match: { topic } },
      { $lookup: { from: "users", localField: "userId", foreignField: "_id", as: "user" } },
      { $unwind: "$user" },
      { $project: { 
        _id: 1, 
        score: 1, 
        totalQuestions: 1, 
        percentage: 1, 
        dateTaken: 1, 
        username: "$user.name" 
      }},
      { $sort: { score: -1, percentage: -1, dateTaken: 1 } },
      { $skip: skip },
      { $limit: limit }
    ]);
    
    const total = await QuizHistory.countDocuments({ topic });
    
    res.json({
      leaderboard,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) { 
    console.error("Leaderboard error:", error); 
    res.status(500).json({ error: "Failed to load leaderboard" }); 
  }
});

// Dashboard Summary Route
router.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const history = await QuizHistory.find({ userId });
    
    if (history.length === 0) {
      return res.json({ 
        totalQuizzes: 0, 
        bestScore: 0, 
        averageScore: 0, 
        topics: [], 
        badges: [],
        lastActivity: null
      });
    }

    const totalQuizzes = history.length;
    const bestScore = Math.max(...history.map(h => h.score));
    const totalPossible = history.reduce((sum, h) => sum + h.totalQuestions, 0);
    const totalCorrect = history.reduce((sum, h) => sum + h.score, 0);
    const averageScore = totalPossible > 0 ? Math.round((totalCorrect / totalPossible) * 100) : 0;
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
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile with validation
router.put('/profile', authenticateToken, [
  body('name').trim().isLength({ min: 1, max: 50 }).withMessage('Name must be between 1-50 characters')
], validate, async (req, res) => {
  try {
    const { name } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { name },
      { new: true, runValidators: true }
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

// Change password with validation
router.put('/change-password', authenticateToken, [
  body('currentPassword').exists().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
], validate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user.userId).select('+password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    user.refreshToken = null; // Invalidate all refresh tokens on password change
    await user.save();
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Final route setup
app.use('/api', router);

// Enhanced Error handling middleware
app.use((error, req, res, next) => {
  console.error(error.stack);
  
  // Mongoose validation error
  if (error.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Validation Error',
      details: Object.values(error.errors).map(e => e.message)
    });
  }
  
  // Mongoose duplicate key error
  if (error.code === 11000) {
    return res.status(400).json({ 
      error: 'Duplicate field value entered',
      details: 'This value already exists in our system'
    });
  }
  
  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }
  
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : error.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Server Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});

export default app;