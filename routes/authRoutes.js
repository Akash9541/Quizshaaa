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
import rateLimit from 'express-rate-limit';

const router = express.Router();

// Login limiters
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts, please try again later.' }
});

router.post('/signup', signup);
router.post('/verify-otp', verifyOtp);
router.post('/resend-otp', resendOtp);
router.post('/login', loginLimiter, login);
router.post('/refresh-token', refreshToken);
router.post('/logout', authenticateToken, logout);
router.get('/profile', authenticateToken, getProfile);
router.post('/contact', contactParams);

export default router;
