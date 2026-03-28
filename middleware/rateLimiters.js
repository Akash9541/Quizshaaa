import rateLimit from 'express-rate-limit';

const buildJsonLimiter = ({
    windowMs,
    max,
    message,
    standardHeaders = true,
    keyGenerator
}) => rateLimit({
    windowMs,
    max,
    standardHeaders,
    legacyHeaders: false,
    keyGenerator,
    skip: (req) => req.path === '/api/health',
    handler: (req, res) => {
        res.status(429).json({
            error: message
        });
    }
});

export const apiLimiter = buildJsonLimiter({
    windowMs: 15 * 60 * 1000,
    max: 150,
    message: 'Too many API requests. Please slow down and try again shortly.'
});

export const authLimiter = buildJsonLimiter({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many authentication attempts. Please try again later.'
});

export const loginLimiter = buildJsonLimiter({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.'
});

export const otpVerifyLimiter = buildJsonLimiter({
    windowMs: 10 * 60 * 1000,
    max: 10,
    message: 'Too many OTP verification attempts. Please wait before trying again.'
});

export const otpResendLimiter = buildJsonLimiter({
    windowMs: 10 * 60 * 1000,
    max: 5,
    message: 'Too many OTP resend requests. Please wait before requesting another code.'
});

export const refreshTokenLimiter = buildJsonLimiter({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many token refresh attempts. Please log in again.'
});

export const questionGenerationLimiter = buildJsonLimiter({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: 'Too many quiz generation requests. Please try again in a few minutes.'
});

export const quizWriteLimiter = buildJsonLimiter({
    windowMs: 15 * 60 * 1000,
    max: 60,
    message: 'Too many quiz submissions. Please wait a moment and try again.'
});

export const leaderboardLimiter = buildJsonLimiter({
    windowMs: 5 * 60 * 1000,
    max: 120,
    message: 'Too many leaderboard requests. Please wait a bit and try again.'
});

export const liveDebugLimiter = buildJsonLimiter({
    windowMs: 5 * 60 * 1000,
    max: 30,
    message: 'Too many live room diagnostics requests. Please wait a moment and try again.'
});
