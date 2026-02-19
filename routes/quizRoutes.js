import express from 'express';
import {
    saveQuizHistory,
    getQuizHistory,
    getLeaderboard,
    getDashboardStats,
    getRecentQuizzes,
    getUserStats
} from '../controllers/quizController.js';
import authenticateToken from '../middleware/authMiddleware.js';

const router = express.Router();

router.post("/history", authenticateToken, saveQuizHistory);
router.get("/history", authenticateToken, getQuizHistory);
router.get("/leaderboard/:topic", getLeaderboard);
router.get("/dashboard", authenticateToken, getDashboardStats);
router.get("/recent-quizzes", authenticateToken, getRecentQuizzes);
router.get("/stats", authenticateToken, getUserStats);

export default router;
