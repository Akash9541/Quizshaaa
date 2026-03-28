import express from 'express';
import {
    signup,
    verifyOtp,
    resendOtp,
    login,
    refreshToken,
    logout,
    getProfile,
    contactParams
} from '../controllers/authController.js';
import authenticateToken from '../middleware/authMiddleware.js';
import {
    authLimiter,
    loginLimiter,
    otpResendLimiter,
    otpVerifyLimiter,
    refreshTokenLimiter
} from '../middleware/rateLimiters.js';

const router = express.Router();

router.post('/signup', authLimiter, signup);
router.post('/verify-otp', otpVerifyLimiter, verifyOtp);
router.post('/resend-otp', otpResendLimiter, resendOtp);
router.post('/login', loginLimiter, login);
router.post('/refresh-token', refreshTokenLimiter, refreshToken);
router.post('/logout', authenticateToken, logout);
router.get('/profile', authenticateToken, getProfile);
router.post('/contact', authLimiter, contactParams);

export default router;
