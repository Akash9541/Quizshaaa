import express from 'express';
import rateLimit from 'express-rate-limit';
import { sendEmailOtp } from '../controllers/emailController.js';

const router = express.Router();

const sendEmailLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many email requests. Please try again later.' }
});

router.post('/send-email', sendEmailLimiter, sendEmailOtp);

export default router;
