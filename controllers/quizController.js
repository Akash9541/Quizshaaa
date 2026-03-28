import QuizHistory from '../models/QuizHistory.js';
import { deleteCacheKey, getCachedJson, setCachedJson } from '../services/cacheService.js';
import { getHybridQuestions } from '../services/questionGenerationService.js';
import { enqueueQuizResultProcessing } from '../services/quizQueue.js';
import { emitTopicLeaderboardUpdate } from '../services/socketServer.js';
import { buildDashboardStats, buildLeaderboard, buildRecentQuizzes, buildUserStats } from '../services/statsService.js';
import { buildLiveRoomDiagnostics, getActiveTimedRooms, getIndexedLiveRooms } from '../services/liveSessionStore.js';
import { logger } from '../services/logger.js';
import { isRedisReady } from '../services/redisClient.js';
import { getSocketServerStatus } from '../services/socketServer.js';
import { normalizeDifficulty, normalizeTopic } from '../utils/quizTopics.js';

const DASHBOARD_CACHE_TTL_SECONDS = 5 * 60;
const LEADERBOARD_CACHE_TTL_SECONDS = 2 * 60;
const RECENT_QUIZZES_CACHE_TTL_SECONDS = 5 * 60;
const USER_STATS_CACHE_TTL_SECONDS = 5 * 60;

export const getQuizQuestions = async (req, res) => {
    try {
        const { topic, difficulty = 'medium', limit = 5 } = req.query;
        const normalizedTopic = normalizeTopic(topic);
        const normalizedDifficulty = normalizeDifficulty(difficulty);

        if (!normalizedTopic) {
            return res.status(400).json({ error: 'Invalid topic' });
        }

        if (!normalizedDifficulty) {
            return res.status(400).json({ error: 'Invalid difficulty' });
        }

        const result = await getHybridQuestions({
            topic: normalizedTopic,
            difficulty: normalizedDifficulty,
            limit
        });

        res.json({
            topic: normalizedTopic,
            difficulty: normalizedDifficulty,
            source: result.source,
            fallbackReason: result.fallbackReason,
            questions: result.questions
        });
    } catch (error) {
        logger.error('Quiz generation error', { error: error.message });
        res.status(500).json({ error: 'Failed to generate quiz questions' });
    }
};

export const saveQuizHistory = async (req, res) => {
    try {
        const { topic, quizTitle, score, totalQuestions } = req.body;
        const normalizedTopic = normalizeTopic(topic || quizTitle);
        if (!normalizedTopic || score == null || totalQuestions == null) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const numericScore = Number(score);
        const numericTotal = Number(totalQuestions);
        if (Number.isNaN(numericScore) || Number.isNaN(numericTotal) || numericTotal <= 0) {
            return res.status(400).json({ error: "Invalid score or totalQuestions" });
        }

        const history = new QuizHistory({
            userId: req.user.userId,
            topic: normalizedTopic,
            score: numericScore,
            totalQuestions: numericTotal
        });
        await history.save();

        await Promise.all([
            deleteCacheKey(`dashboard:${req.user.userId}`),
            deleteCacheKey(`recent-quizzes:${req.user.userId}`),
            deleteCacheKey(`user-stats:${req.user.userId}`),
            deleteCacheKey(`leaderboard:${normalizedTopic}`)
        ]);

        try {
            await enqueueQuizResultProcessing({
                userId: req.user.userId,
                topic: normalizedTopic
            });
        } catch (queueError) {
            logger.warn(`Quiz queue enqueue skipped: ${queueError.message}`);
        }

        emitTopicLeaderboardUpdate(normalizedTopic, {
            userName: req.user.name,
            score: numericScore,
            totalQuestions: numericTotal
        }).catch((socketError) => {
            logger.warn(`Realtime leaderboard emit skipped: ${socketError.message}`);
        });

        res.status(201).json({ message: "History saved", history });
    } catch (error) {
        logger.error('Save history error', { error: error.message });
        res.status(500).json({ error: "Failed to save history" });
    }
};

export const getQuizHistory = async (req, res) => {
    try {
        const history = await QuizHistory.find({ userId: req.user.userId }).sort({ dateTaken: -1 });
        res.json(history);
    } catch (error) {
        logger.error('Fetch history error', { error: error.message });
        res.status(500).json({ error: 'Failed to fetch history' });
    }
};

export const getLeaderboard = async (req, res) => {
    const { topic } = req.params;
    const normalizedTopic = normalizeTopic(topic);
    if (!normalizedTopic) return res.status(400).json({ error: "Invalid topic" });
    try {
        const cacheKey = `leaderboard:${normalizedTopic}`;
        const cachedLeaderboard = await getCachedJson(cacheKey);
        if (cachedLeaderboard) {
            return res.json(cachedLeaderboard);
        }

        const leaderboard = await buildLeaderboard(normalizedTopic);
        await setCachedJson(cacheKey, leaderboard, LEADERBOARD_CACHE_TTL_SECONDS);
        res.json(leaderboard);
    } catch (error) {
        logger.error('Leaderboard error', { error: error.message });
        res.status(500).json({ error: "Failed to load leaderboard" });
    }
};

export const getDashboardStats = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `dashboard:${userId}`;
        const cachedDashboard = await getCachedJson(cacheKey);
        if (cachedDashboard) {
            return res.json(cachedDashboard);
        }

        const dashboard = await buildDashboardStats(userId);
        await setCachedJson(cacheKey, dashboard, DASHBOARD_CACHE_TTL_SECONDS);
        res.json(dashboard);
    } catch (error) {
        logger.error('Dashboard error', { error: error.message });
        res.status(500).json({ error: "Failed to load dashboard" });
    }
};

export const getRecentQuizzes = async (req, res) => { // Added missing endpoint
    try {
        const userId = req.user.userId;
        const cacheKey = `recent-quizzes:${userId}`;
        const cachedRecentQuizzes = await getCachedJson(cacheKey);
        if (cachedRecentQuizzes) {
            return res.json(cachedRecentQuizzes);
        }

        const recentQuizzes = await buildRecentQuizzes(userId);
        await setCachedJson(cacheKey, recentQuizzes, RECENT_QUIZZES_CACHE_TTL_SECONDS);
        res.json(recentQuizzes);
    } catch (error) {
        logger.error('Recent quizzes error', { error: error.message });
        res.status(500).json({ error: "Failed to load recent quizzes" });
    }
};

export const getUserStats = async (req, res) => { // Added handler for /stats
    try {
        const userId = req.user.userId;
        const cacheKey = `user-stats:${userId}`;
        const cachedUserStats = await getCachedJson(cacheKey);
        if (cachedUserStats) {
            return res.json(cachedUserStats);
        }

        const userStats = await buildUserStats(userId);
        await setCachedJson(cacheKey, userStats, USER_STATS_CACHE_TTL_SECONDS);
        res.json(userStats);
    } catch (error) {
        logger.error('User stats error', { error: error.message });
        res.status(500).json({ error: "Failed to load user stats" });
    }
};

export const getLiveRoomsHealth = async (req, res) => {
    try {
        const [indexedRooms, timedRooms] = await Promise.all([
            getIndexedLiveRooms(),
            getActiveTimedRooms()
        ]);

        const rooms = await Promise.all(indexedRooms.map((roomId) => buildLiveRoomDiagnostics(roomId)));
        const activeRooms = rooms.filter(Boolean);

        res.json({
            timestamp: new Date().toISOString(),
            requestedBy: {
                userId: req.user.userId,
                name: req.user.name
            },
            services: {
                redis: isRedisReady() ? 'connected' : 'disconnected',
                socket: getSocketServerStatus()
            },
            liveRooms: {
                indexedCount: indexedRooms.length,
                timedCount: timedRooms.length,
                rooms: activeRooms
            }
        });
    } catch (error) {
        logger.error('Live room health error', { error: error.message });
        res.status(500).json({ error: 'Failed to load live room diagnostics' });
    }
};
