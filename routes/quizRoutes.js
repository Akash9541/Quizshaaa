import express from 'express';
import {
    getQuizQuestions,
    saveQuizHistory,
    getQuizHistory,
    getLeaderboard,
    getDashboardStats,
    getRecentQuizzes,
    getUserStats,
    getLiveRoomsHealth
} from '../controllers/quizController.js';
import authenticateToken from '../middleware/authMiddleware.js';
import {
    leaderboardLimiter,
    liveDebugLimiter,
    questionGenerationLimiter,
    quizWriteLimiter
} from '../middleware/rateLimiters.js';

const router = express.Router();

router.get("/questions", questionGenerationLimiter, authenticateToken, getQuizQuestions);
router.post("/history", quizWriteLimiter, authenticateToken, saveQuizHistory);
router.get("/history", authenticateToken, getQuizHistory);
router.get("/leaderboard/:topic", leaderboardLimiter, getLeaderboard);
router.get("/dashboard", authenticateToken, getDashboardStats);
router.get("/recent-quizzes", authenticateToken, getRecentQuizzes);
router.get("/stats", authenticateToken, getUserStats);
router.get("/live/health", liveDebugLimiter, authenticateToken, getLiveRoomsHealth);

export default router;
