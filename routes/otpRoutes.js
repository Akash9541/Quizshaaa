import express from 'express';
import { resetPassword, sendOtp, verifyOtp } from '../controllers/otpController.js';
import { authLimiter, otpVerifyLimiter } from '../middleware/rateLimiters.js';

const router = express.Router();

router.post('/send-otp', authLimiter, sendOtp);
router.post('/verify-otp-code', otpVerifyLimiter, verifyOtp);
router.post('/reset-password', authLimiter, resetPassword);

export default router;
