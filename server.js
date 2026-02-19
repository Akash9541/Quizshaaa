import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import session from 'express-session';
import MongoStore from 'connect-mongo';

import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import quizRoutes from './routes/quizRoutes.js';
import otpRoutes from './routes/otpRoutes.js';

// Load Environment Variables
dotenv.config();

// Initialize Express App
const app = express();
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());

const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.BACKEND_URL,
  'https://quizzshaala.onrender.com',
  'https://quizshaala.onrender.com',
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000'
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  optionsSuccessStatus: 200
}));

// Session Management
console.log("SESSION_SECRET =", process.env.SESSION_SECRET ? "Set" : "Not Set");

let sessionStore;
if (process.env.USE_MONGO_SESSION_STORE === 'true') {
  try {
    sessionStore = MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      ttl: 24 * 60 * 60 // 1 day
    });
  } catch (error) {
    console.warn('Mongo session store unavailable, using memory session store.');
  }
}

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  ...(sessionStore ? { store: sessionStore } : {}),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Connect to Database
connectDB();

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// Routes
app.use('/api', authRoutes);
app.use('/api', quizRoutes);
app.use('/api', otpRoutes);

// Health check
app.get('/api/health', (req, res) => res.json({
  status: 'Server is running',
  timestamp: new Date().toISOString()
}));

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
