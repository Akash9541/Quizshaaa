import { Redis } from 'ioredis';
import { logger } from './logger.js';

const DEFAULT_REDIS_URL = process.env.REDIS_URL || '';

let redis = null;
let redisEnabled = false;

if (DEFAULT_REDIS_URL) {
    redis = new Redis(DEFAULT_REDIS_URL, {
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        lazyConnect: true
    });

    redis.on('ready', () => {
        redisEnabled = true;
        logger.info('Connected to Redis');
    });

    redis.on('error', (error) => {
        redisEnabled = false;
        logger.warn(`Redis unavailable: ${error.message}`);
    });
}

export const getRedisClient = () => redis;

export const createRedisDuplicate = () => {
    if (!redis) {
        return null;
    }

    return redis.duplicate({
        lazyConnect: true,
        enableReadyCheck: false,
        maxRetriesPerRequest: null
    });
};

export const connectRedis = async () => {
    if (!redis) {
        return null;
    }

    if (redis.status === 'ready' || redis.status === 'connecting') {
        return redis;
    }

    try {
        await redis.connect();
        return redis;
    } catch (error) {
        redisEnabled = false;
        logger.warn(`Redis connection skipped: ${error.message}`);
        return null;
    }
};

export const isRedisReady = () => Boolean(redis && redisEnabled);
