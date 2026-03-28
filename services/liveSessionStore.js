import { connectRedis, getRedisClient, isRedisReady } from './redisClient.js';

const ROOM_TTL_SECONDS = Math.max(Number(process.env.LIVE_ROOM_TTL_SECONDS || 3600), 300);
const COMPLETED_ROOM_TTL_SECONDS = Math.max(Number(process.env.LIVE_ROOM_COMPLETED_TTL_SECONDS || 900), 120);
const EMPTY_ROOM_TTL_SECONDS = Math.max(Number(process.env.LIVE_ROOM_EMPTY_TTL_SECONDS || 120), 30);

const ROOM_INDEX_KEY = 'live:rooms:index';
const ROOM_TIMER_INDEX_KEY = 'live:rooms:timers';

const serialize = (value) => JSON.stringify(value);
const parse = (value, fallback = null) => {
    try {
        return value ? JSON.parse(value) : fallback;
    } catch {
        return fallback;
    }
};

const ensureRedis = async () => {
    if (!getRedisClient()) {
        return null;
    }

    if (!isRedisReady()) {
        await connectRedis();
    }

    return isRedisReady() ? getRedisClient() : null;
};

const nowIso = () => new Date().toISOString();

const keyFactory = {
    meta: (roomId) => `live:room:${roomId}:meta`,
    questions: (roomId) => `live:room:${roomId}:questions`,
    participants: (roomId) => `live:room:${roomId}:participants`,
    participant: (roomId, socketId) => `live:room:${roomId}:participant:${socketId}`,
    answers: (roomId, socketId) => `live:room:${roomId}:answers:${socketId}`,
    answerLog: (roomId, socketId) => `live:room:${roomId}:answerlog:${socketId}`,
    leaderboard: (roomId) => `live:room:${roomId}:leaderboard`,
    timer: (roomId) => `live:room:${roomId}:timer`,
    lockAdvance: (roomId) => `live:room:${roomId}:lock:advance`,
    lockTick: (roomId) => `live:room:${roomId}:lock:tick`
};

const getRoomKeys = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        throw new Error('Redis is required for live sessions.');
    }

    const participantIds = await redis.smembers(keyFactory.participants(roomId));
    const keys = [
        keyFactory.meta(roomId),
        keyFactory.questions(roomId),
        keyFactory.participants(roomId),
        keyFactory.leaderboard(roomId),
        keyFactory.timer(roomId)
    ];

    participantIds.forEach((socketId) => {
        keys.push(
            keyFactory.participant(roomId, socketId),
            keyFactory.answers(roomId, socketId),
            keyFactory.answerLog(roomId, socketId)
        );
    });

    return { redis, participantIds, keys };
};

const findParticipantByUserName = async (redis, roomId, userName) => {
    const participantIds = await redis.smembers(keyFactory.participants(roomId));

    for (const participantId of participantIds) {
        const participantName = await redis.hget(keyFactory.participant(roomId, participantId), 'userName');
        if (participantName === userName) {
            return participantId;
        }
    }

    return null;
};

const applyRoomTtl = async (roomId, ttlSeconds = ROOM_TTL_SECONDS) => {
    const { redis, keys } = await getRoomKeys(roomId);
    if (!keys.length) {
        return;
    }

    const pipeline = redis.pipeline();
    keys.forEach((key) => pipeline.expire(key, ttlSeconds));
    pipeline.expire(ROOM_INDEX_KEY, ttlSeconds);
    pipeline.expire(ROOM_TIMER_INDEX_KEY, ttlSeconds);
    await pipeline.exec();
};

export const createLiveRoomSession = async ({
    roomId,
    topic,
    difficulty,
    hostSocketId,
    hostName,
    questionDurationMs,
    questions
}) => {
    const redis = await ensureRedis();
    if (!redis) {
        throw new Error('Redis is required for live sessions.');
    }

    const timestamp = nowIso();
    const metaKey = keyFactory.meta(roomId);
    const timerKey = keyFactory.timer(roomId);

    await redis
        .multi()
        .hset(metaKey, {
            roomId,
            topic,
            difficulty,
            hostSocketId,
            hostName,
            status: 'waiting',
            currentQuestionIndex: -1,
            questionDurationMs,
            totalQuestions: questions.length,
            createdAt: timestamp,
            updatedAt: timestamp,
            questionStartedAt: '',
            lastActivityAt: timestamp
        })
        .set(keyFactory.questions(roomId), serialize(questions))
        .hset(timerKey, {
            questionStartedAt: '',
            questionDurationMs,
            expiresAt: ''
        })
        .sadd(ROOM_INDEX_KEY, roomId)
        .exec();

    await applyRoomTtl(roomId);
};

export const addLiveParticipant = async (roomId, socketId, userName) => {
    const redis = await ensureRedis();
    if (!redis) {
        throw new Error('Redis is required for live sessions.');
    }

    const timestamp = nowIso();
    const trimmedName = (userName || '').trim() || `Guest-${socketId.slice(-4)}`;
    const metaKey = keyFactory.meta(roomId);
    const previousSocketId = await findParticipantByUserName(redis, roomId, trimmedName);

    if (previousSocketId && previousSocketId !== socketId) {
        const [meta, previousParticipant, previousAnswers, previousAnswerLog] = await Promise.all([
            redis.hgetall(metaKey),
            redis.hgetall(keyFactory.participant(roomId, previousSocketId)),
            redis.hgetall(keyFactory.answers(roomId, previousSocketId)),
            redis.lrange(keyFactory.answerLog(roomId, previousSocketId), 0, -1)
        ]);

        const restoredScore = Number(previousParticipant.score || 0);
        const restoredAnswersSubmitted = Number(previousParticipant.answersSubmitted || 0);
        const joinedAt = previousParticipant.joinedAt || timestamp;

        const pipeline = redis.multi();
        pipeline.srem(keyFactory.participants(roomId), previousSocketId);
        pipeline.sadd(keyFactory.participants(roomId), socketId);
        pipeline.del(
            keyFactory.participant(roomId, previousSocketId),
            keyFactory.answers(roomId, previousSocketId),
            keyFactory.answerLog(roomId, previousSocketId)
        );
        pipeline.hset(keyFactory.participant(roomId, socketId), {
            socketId,
            userName: trimmedName,
            score: restoredScore,
            answersSubmitted: restoredAnswersSubmitted,
            joinedAt
        });

        if (Object.keys(previousAnswers).length) {
            pipeline.hset(keyFactory.answers(roomId, socketId), previousAnswers);
        }

        if (previousAnswerLog.length) {
            pipeline.rpush(keyFactory.answerLog(roomId, socketId), ...previousAnswerLog);
        }

        pipeline.zrem(keyFactory.leaderboard(roomId), previousSocketId);
        pipeline.zadd(keyFactory.leaderboard(roomId), restoredScore, socketId);

        if (meta.hostSocketId === previousSocketId || meta.hostName === trimmedName) {
            pipeline.hset(metaKey, {
                hostSocketId: socketId,
                hostName: trimmedName,
                updatedAt: timestamp,
                lastActivityAt: timestamp
            });
        } else {
            pipeline.hset(metaKey, {
                updatedAt: timestamp,
                lastActivityAt: timestamp
            });
        }

        await pipeline.exec();
        await applyRoomTtl(roomId);
        return trimmedName;
    }

    await redis
        .multi()
        .sadd(keyFactory.participants(roomId), socketId)
        .hset(keyFactory.participant(roomId, socketId), {
            socketId,
            userName: trimmedName,
            score: 0,
            answersSubmitted: 0,
            joinedAt: timestamp
        })
        .zadd(keyFactory.leaderboard(roomId), 0, socketId)
        .hset(metaKey, {
            updatedAt: timestamp,
            lastActivityAt: timestamp
        })
        .exec();

    await applyRoomTtl(roomId);
    return trimmedName;
};

export const removeLiveParticipant = async (roomId, socketId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return null;
    }

    const currentHost = await redis.hget(keyFactory.meta(roomId), 'hostSocketId');
    const participantIds = await redis.smembers(keyFactory.participants(roomId));
    const remainingIds = participantIds.filter((entry) => entry !== socketId);

    const pipeline = redis.multi();
    pipeline.srem(keyFactory.participants(roomId), socketId);
    pipeline.zrem(keyFactory.leaderboard(roomId), socketId);
    pipeline.del(
        keyFactory.participant(roomId, socketId),
        keyFactory.answers(roomId, socketId),
        keyFactory.answerLog(roomId, socketId)
    );

    const updates = {
        updatedAt: nowIso(),
        lastActivityAt: nowIso()
    };

    if (currentHost === socketId && remainingIds.length) {
        const nextHostId = remainingIds[0];
        const nextHostName = await redis.hget(keyFactory.participant(roomId, nextHostId), 'userName');
        updates.hostSocketId = nextHostId;
        updates.hostName = nextHostName || `Guest-${nextHostId.slice(-4)}`;
    }

    pipeline.hset(keyFactory.meta(roomId), updates);
    await pipeline.exec();

    if (remainingIds.length) {
        await applyRoomTtl(roomId);
        return {
            remainingParticipants: remainingIds.length
        };
    }

    await expireLiveRoom(roomId, EMPTY_ROOM_TTL_SECONDS);
    return {
        remainingParticipants: 0
    };
};

export const startLiveRoom = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        throw new Error('Redis is required for live sessions.');
    }

    const now = Date.now();
    const questionDurationMs = Number(await redis.hget(keyFactory.meta(roomId), 'questionDurationMs'));

    await redis
        .multi()
        .hset(keyFactory.meta(roomId), {
            status: 'in_progress',
            currentQuestionIndex: 0,
            questionStartedAt: now,
            updatedAt: nowIso(),
            lastActivityAt: nowIso()
        })
        .hset(keyFactory.timer(roomId), {
            questionStartedAt: now,
            questionDurationMs,
            expiresAt: now + questionDurationMs
        })
        .sadd(ROOM_TIMER_INDEX_KEY, roomId)
        .exec();

    await applyRoomTtl(roomId);
};

export const completeLiveRoom = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return;
    }

    await redis
        .multi()
        .hset(keyFactory.meta(roomId), {
            status: 'completed',
            updatedAt: nowIso(),
            lastActivityAt: nowIso()
        })
        .hset(keyFactory.timer(roomId), {
            questionStartedAt: '',
            expiresAt: ''
        })
        .srem(ROOM_TIMER_INDEX_KEY, roomId)
        .exec();

    await expireLiveRoom(roomId, COMPLETED_ROOM_TTL_SECONDS);
};

export const advanceLiveRoomQuestion = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        throw new Error('Redis is required for live sessions.');
    }

    const metaKey = keyFactory.meta(roomId);
    const [currentQuestionIndex, totalQuestions, questionDurationMs, status] = await redis.hmget(
        metaKey,
        'currentQuestionIndex',
        'totalQuestions',
        'questionDurationMs',
        'status'
    );

    if (status !== 'in_progress') {
        return null;
    }

    const nextIndex = Number(currentQuestionIndex) + 1;
    if (nextIndex >= Number(totalQuestions)) {
        await completeLiveRoom(roomId);
        return { completed: true };
    }

    const now = Date.now();
    await redis
        .multi()
        .hset(metaKey, {
            currentQuestionIndex: nextIndex,
            questionStartedAt: now,
            updatedAt: nowIso(),
            lastActivityAt: nowIso()
        })
        .hset(keyFactory.timer(roomId), {
            questionStartedAt: now,
            questionDurationMs: Number(questionDurationMs),
            expiresAt: now + Number(questionDurationMs)
        })
        .exec();

    await applyRoomTtl(roomId);
    return { completed: false, currentQuestionIndex: nextIndex };
};

export const submitLiveAnswer = async ({ roomId, socketId, questionIndex, selectedOption }) => {
    const redis = await ensureRedis();
    if (!redis) {
        throw new Error('Redis is required for live sessions.');
    }

    const [meta, questionPayload, participant] = await Promise.all([
        redis.hgetall(keyFactory.meta(roomId)),
        redis.get(keyFactory.questions(roomId)),
        redis.hgetall(keyFactory.participant(roomId, socketId))
    ]);

    if (!meta?.roomId) {
        throw new Error('Live room not found.');
    }

    if (meta.status !== 'in_progress') {
        throw new Error('Live room is not accepting answers right now.');
    }

    if (Number(meta.currentQuestionIndex) !== Number(questionIndex)) {
        throw new Error('Question index mismatch. Follow the server timer.');
    }

    if (!participant?.socketId) {
        throw new Error('Participant is not part of this room.');
    }

    const answerSet = await redis.hsetnx(
        keyFactory.answers(roomId, socketId),
        String(questionIndex),
        serialize({
            selectedOption,
            answeredAt: nowIso()
        })
    );

    if (answerSet === 0) {
        throw new Error('Answer already submitted for this question.');
    }

    const questions = parse(questionPayload, []);
    const question = questions[questionIndex];
    const isCorrect = question?.answer === selectedOption;
    const answeredAt = nowIso();
    const nextScore = Number(participant.score || 0) + (isCorrect ? 1 : 0);

    await redis
        .multi()
        .hset(keyFactory.participant(roomId, socketId), {
            score: nextScore,
            answersSubmitted: Number(participant.answersSubmitted || 0) + 1
        })
        .zadd(keyFactory.leaderboard(roomId), nextScore, socketId)
        .rpush(keyFactory.answerLog(roomId, socketId), serialize({
            questionIndex,
            selectedOption,
            answeredAt,
            isCorrect
        }))
        .hset(keyFactory.meta(roomId), {
            updatedAt: nowIso(),
            lastActivityAt: nowIso()
        })
        .exec();

    await applyRoomTtl(roomId);
    return { isCorrect };
};

export const getLiveRoomMeta = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return null;
    }

    const meta = await redis.hgetall(keyFactory.meta(roomId));
    return meta?.roomId ? meta : null;
};

export const getLiveRoomQuestions = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return [];
    }

    return parse(await redis.get(keyFactory.questions(roomId)), []);
};

export const getLiveRoomLeaderboard = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return [];
    }

    const memberScores = await redis.zrevrange(keyFactory.leaderboard(roomId), 0, -1, 'WITHSCORES');
    const leaderboard = [];

    for (let index = 0; index < memberScores.length; index += 2) {
        const socketId = memberScores[index];
        const score = Number(memberScores[index + 1]);
        const participant = await redis.hgetall(keyFactory.participant(roomId, socketId));
        const answers = await redis.lrange(keyFactory.answerLog(roomId, socketId), 0, -1);

        if (!participant?.socketId) {
            continue;
        }

        leaderboard.push({
            socketId,
            userName: participant.userName,
            score,
            answersSubmitted: Number(participant.answersSubmitted || 0),
            answerTimestamps: answers.map((entry) => parse(entry, {}))
        });
    }

    return leaderboard;
};

export const buildLiveSessionState = async (roomId, socketId = null) => {
    const meta = await getLiveRoomMeta(roomId);
    if (!meta) {
        return null;
    }

    const questions = await getLiveRoomQuestions(roomId);
    const participantCount = await getLiveParticipantCount(roomId);
    const currentQuestionIndex = Number(meta.currentQuestionIndex);
    const questionDurationMs = Number(meta.questionDurationMs);
    const questionStartedAt = meta.questionStartedAt ? Number(meta.questionStartedAt) : null;
    const expiresAt = meta.status === 'in_progress' && questionStartedAt
        ? questionStartedAt + questionDurationMs
        : null;
    const remainingSeconds = expiresAt
        ? Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000))
        : meta.status === 'completed'
            ? 0
            : Math.ceil(questionDurationMs / 1000);
    const currentQuestion = meta.status === 'in_progress' && questions[currentQuestionIndex]
        ? {
            id: questions[currentQuestionIndex].id || `question-${currentQuestionIndex + 1}`,
            question: questions[currentQuestionIndex].question,
            options: questions[currentQuestionIndex].options
        }
        : null;

    return {
        roomId: meta.roomId,
        topic: meta.topic,
        difficulty: meta.difficulty,
        hostName: meta.hostName,
        isHost: socketId ? meta.hostSocketId === socketId : false,
        status: meta.status,
        currentQuestionIndex,
        totalQuestions: Number(meta.totalQuestions),
        remainingSeconds,
        questionDurationSeconds: Math.ceil(questionDurationMs / 1000),
        currentQuestion,
        activeParticipants: participantCount
    };
};

export const getLiveParticipantCount = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return 0;
    }

    return redis.scard(keyFactory.participants(roomId));
};

export const getActiveTimedRooms = async () => {
    const redis = await ensureRedis();
    if (!redis) {
        return [];
    }

    return redis.smembers(ROOM_TIMER_INDEX_KEY);
};

export const getIndexedLiveRooms = async () => {
    const redis = await ensureRedis();
    if (!redis) {
        return [];
    }

    return redis.smembers(ROOM_INDEX_KEY);
};

export const getLiveRoomTimerState = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return null;
    }

    const timer = await redis.hgetall(keyFactory.timer(roomId));
    return Object.keys(timer).length ? timer : null;
};

export const buildLiveRoomDiagnostics = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return null;
    }

    const [meta, timer, participantCount, leaderboardSize] = await Promise.all([
        getLiveRoomMeta(roomId),
        getLiveRoomTimerState(roomId),
        getLiveParticipantCount(roomId),
        redis.zcard(keyFactory.leaderboard(roomId))
    ]);

    if (!meta?.roomId) {
        return null;
    }

    return {
        roomId: meta.roomId,
        topic: meta.topic,
        difficulty: meta.difficulty,
        status: meta.status,
        hostName: meta.hostName,
        currentQuestionIndex: Number(meta.currentQuestionIndex),
        totalQuestions: Number(meta.totalQuestions),
        participantCount,
        leaderboardEntries: leaderboardSize,
        questionDurationMs: Number(meta.questionDurationMs),
        lastActivityAt: meta.lastActivityAt,
        timer: timer
            ? {
                questionStartedAt: timer.questionStartedAt ? Number(timer.questionStartedAt) : null,
                expiresAt: timer.expiresAt ? Number(timer.expiresAt) : null
            }
            : null
    };
};

export const acquireLiveRoomLock = async (lockKey, ttlMs) => {
    const redis = await ensureRedis();
    if (!redis) {
        return false;
    }

    const result = await redis.set(lockKey, nowIso(), 'PX', ttlMs, 'NX');
    return result === 'OK';
};

export const expireLiveRoom = async (roomId, ttlSeconds) => {
    const { redis, keys } = await getRoomKeys(roomId);
    const pipeline = redis.pipeline();

    keys.forEach((key) => pipeline.expire(key, ttlSeconds));
    pipeline.srem(ROOM_TIMER_INDEX_KEY, roomId);
    await pipeline.exec();
};

export const deleteLiveRoomIfExpired = async (roomId) => {
    const redis = await ensureRedis();
    if (!redis) {
        return;
    }

    const exists = await redis.exists(keyFactory.meta(roomId));
    if (!exists) {
        await redis.srem(ROOM_INDEX_KEY, roomId);
        await redis.srem(ROOM_TIMER_INDEX_KEY, roomId);
    }
};

export const liveRoomKeys = keyFactory;
