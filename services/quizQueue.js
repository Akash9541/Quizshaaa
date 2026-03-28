import { Queue, Worker } from 'bullmq';

import { deleteCacheKey, deleteCachePattern, setCachedJson } from './cacheService.js';
import { logger } from './logger.js';
import { buildDashboardStats, buildLeaderboard, buildRecentQuizzes, buildUserStats } from './statsService.js';
import { connectRedis, getRedisClient, isRedisReady } from './redisClient.js';

const QUIZ_QUEUE_NAME = 'quiz-processing';

let quizQueue = null;
let quizWorker = null;

const getQueueConnection = () => {
    const redis = getRedisClient();
    if (!redis) {
        return null;
    }

    return {
        host: redis.options.host,
        port: redis.options.port,
        username: redis.options.username,
        password: redis.options.password,
        db: redis.options.db,
        tls: redis.options.tls
    };
};

const warmUserCaches = async (userId) => {
    const [dashboard, recent, stats] = await Promise.all([
        buildDashboardStats(userId),
        buildRecentQuizzes(userId),
        buildUserStats(userId)
    ]);

    await Promise.all([
        setCachedJson(`dashboard:${userId}`, dashboard, 300),
        setCachedJson(`recent-quizzes:${userId}`, recent, 300),
        setCachedJson(`user-stats:${userId}`, stats, 300)
    ]);
};

const processQuizResultJob = async (job) => {
    const { userId, topic } = job.data;

    await Promise.all([
        deleteCacheKey(`dashboard:${userId}`),
        deleteCacheKey(`recent-quizzes:${userId}`),
        deleteCacheKey(`user-stats:${userId}`),
        deleteCacheKey(`leaderboard:${topic}`),
        deleteCachePattern(`questions:${topic}:*`)
    ]);

    await warmUserCaches(userId);

    if (topic) {
        const leaderboard = await buildLeaderboard(topic);
        if (leaderboard) {
            await setCachedJson(`leaderboard:${topic}`, leaderboard, 120);
        }
    }
};

export const initializeQuizQueue = async () => {
    await connectRedis();
    if (!isRedisReady()) {
        return null;
    }

    if (quizQueue && quizWorker) {
        return quizQueue;
    }

    const connection = getQueueConnection();
    if (!connection) {
        return null;
    }

    quizQueue = new Queue(QUIZ_QUEUE_NAME, { connection });
    quizWorker = new Worker(QUIZ_QUEUE_NAME, processQuizResultJob, { connection });

    quizWorker.on('completed', (job) => {
        logger.info(`Quiz queue job completed: ${job.id}`);
    });

    quizWorker.on('failed', (job, error) => {
        logger.warn(`Quiz queue job failed${job ? ` (${job.id})` : ''}: ${error.message}`);
    });

    return quizQueue;
};

export const enqueueQuizResultProcessing = async ({ userId, topic }) => {
    const queue = await initializeQuizQueue();
    if (!queue) {
        return false;
    }

    await queue.add(
        'quiz-result-saved',
        { userId, topic },
        {
            removeOnComplete: 20,
            removeOnFail: 20
        }
    );

    return true;
};
