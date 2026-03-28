import express from 'express';
import dns from 'node:dns';
import http from 'node:http';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';

import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import quizRoutes from './routes/quizRoutes.js';
import otpRoutes from './routes/otpRoutes.js';
import emailRoutes from './routes/emailRoutes.js';
import { verifyBrevoConfig } from './services/emailService.js';
import { initializeQuizQueue } from './services/quizQueue.js';
import { logger, requestLogger } from './services/logger.js';
import { connectRedis, isRedisReady } from './services/redisClient.js';
import { initializeSocketServer } from './services/socketServer.js';
import { apiLimiter } from './middleware/rateLimiters.js';

// Load Environment Variables
dotenv.config();
dns.setDefaultResultOrder('ipv4first');

// Initialize Express App
const app = express();
const httpServer = http.createServer(app);
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(requestLogger);

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
logger.info('Session secret status loaded', {
  sessionSecretConfigured: Boolean(process.env.SESSION_SECRET)
});

let sessionStore;
if (process.env.USE_MONGO_SESSION_STORE === 'true') {
  try {
    sessionStore = MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      ttl: 24 * 60 * 60 // 1 day
    });
  } catch (error) {
    logger.warn('Mongo session store unavailable, using memory session store.');
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

app.use(apiLimiter);

// Routes
app.use('/api', authRoutes);
app.use('/api', quizRoutes);
app.use('/api', otpRoutes);
app.use('/api/auth', emailRoutes);

// Health check
app.get('/api/health', (req, res) => {
  const databaseConnected = mongoose.connection.readyState === 1;
  const redisConfigured = Boolean(process.env.REDIS_URL);
  const redisConnected = !redisConfigured || isRedisReady();
  const healthy = databaseConnected && redisConnected;

  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'Server is running' : 'Server is degraded',
    timestamp: new Date().toISOString(),
    services: {
      database: databaseConnected ? 'connected' : 'disconnected',
      redis: redisConfigured
        ? (isRedisReady() ? 'connected' : 'disconnected')
        : 'not_configured'
    }
  });
});

const startServer = async () => {
  await connectDB();
  await connectRedis();

  initializeSocketServer(httpServer, allowedOrigins);

  initializeQuizQueue().catch((error) => {
    logger.warn(`Quiz queue unavailable: ${error.message}`);
  });

  verifyBrevoConfig()
    .then(() => logger.info('Brevo email config is ready'))
    .catch((error) => logger.warn(`Brevo email config unavailable: ${error.message}`));

  const PORT = process.env.PORT || 5001;
  httpServer.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
};

startServer().catch((error) => {
  logger.error(`Server startup failed: ${error.message}`);
  process.exit(1);
});
