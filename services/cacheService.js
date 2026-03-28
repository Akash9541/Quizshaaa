import { connectRedis, getRedisClient, isRedisReady } from './redisClient.js';
import { logger } from './logger.js';

const ensureRedis = async () => {
    if (!getRedisClient()) {
        return null;
    }

    if (!isRedisReady()) {
        await connectRedis();
    }

    return isRedisReady() ? getRedisClient() : null;
};

export const getCachedJson = async (key) => {
    try {
        const redis = await ensureRedis();
        if (!redis) {
            return null;
        }

        const value = await redis.get(key);
        if (!value) {
            return null;
        }

        return JSON.parse(value);
    } catch (error) {
        logger.warn(`Redis read skipped for key "${key}": ${error.message}`);
        return null;
    }
};

export const setCachedJson = async (key, value, ttlSeconds) => {
    try {
        const redis = await ensureRedis();
        if (!redis) {
            return false;
        }

        const payload = JSON.stringify(value);
        if (ttlSeconds) {
            await redis.set(key, payload, 'EX', ttlSeconds);
        } else {
            await redis.set(key, payload);
        }

        return true;
    } catch (error) {
        logger.warn(`Redis write skipped for key "${key}": ${error.message}`);
        return false;
    }
};

export const deleteCacheKey = async (key) => {
    try {
        const redis = await ensureRedis();
        if (!redis) {
            return 0;
        }

        return redis.del(key);
    } catch (error) {
        logger.warn(`Redis delete skipped for key "${key}": ${error.message}`);
        return 0;
    }
};

export const deleteCachePattern = async (pattern) => {
    try {
        const redis = await ensureRedis();
        if (!redis) {
            return 0;
        }

        let cursor = '0';
        let deleted = 0;

        do {
            const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
            cursor = nextCursor;

            if (keys.length) {
                deleted += await redis.del(...keys);
            }
        } while (cursor !== '0');

        return deleted;
    } catch (error) {
        logger.warn(`Redis pattern delete skipped for pattern "${pattern}": ${error.message}`);
        return 0;
    }
};
