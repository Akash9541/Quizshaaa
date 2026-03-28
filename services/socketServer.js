import { Server } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';

import { getCachedJson, setCachedJson } from './cacheService.js';
import {
    acquireLiveRoomLock,
    addLiveParticipant,
    advanceLiveRoomQuestion,
    buildLiveSessionState,
    completeLiveRoom,
    createLiveRoomSession,
    deleteLiveRoomIfExpired,
    getActiveTimedRooms,
    getLiveRoomLeaderboard,
    getLiveRoomMeta,
    liveRoomKeys,
    removeLiveParticipant,
    startLiveRoom,
    submitLiveAnswer
} from './liveSessionStore.js';
import { getHybridQuestions } from './questionGenerationService.js';
import { logger } from './logger.js';
import { connectRedis, createRedisDuplicate, isRedisReady } from './redisClient.js';
import { buildLeaderboard } from './statsService.js';
import { normalizeDifficulty, normalizeTopic } from '../utils/quizTopics.js';

const LEADERBOARD_CACHE_TTL_SECONDS = 2 * 60;
const LIVE_ROOM_QUESTION_LIMIT = Math.max(Number(process.env.LIVE_ROOM_QUESTION_LIMIT || 5), 3);
const LIVE_ROOM_QUESTION_DURATION_MS = Math.max(Number(process.env.LIVE_ROOM_QUESTION_DURATION_MS || 30000), 10000);
const LIVE_ROOM_TICK_INTERVAL_MS = Math.max(Number(process.env.LIVE_ROOM_TICK_INTERVAL_MS || 1000), 500);
const LIVE_ROOM_TICK_LOCK_MS = Math.max(Number(process.env.LIVE_ROOM_TICK_LOCK_MS || 800), 250);
const LIVE_ROOM_ADVANCE_LOCK_MS = Math.max(Number(process.env.LIVE_ROOM_ADVANCE_LOCK_MS || 3000), 1000);
const ROOM_ID_ATTEMPTS = 8;

let io = null;
let redisAdapterInitialized = false;
let redisPubClient = null;
let redisSubClient = null;
let roomTimerPoller = null;

const getTopicRoom = (topic) => `topic:${topic}`;
const getLiveRoom = (roomId) => `live:${roomId}`;

const createRoomId = () => Math.random().toString(36).slice(2, 8).toUpperCase();

const emitPresence = async (topic) => {
    if (!io) {
        return;
    }

    const normalizedTopic = normalizeTopic(topic);
    if (!normalizedTopic) {
        return;
    }

    const roomName = getTopicRoom(normalizedTopic);
    const sockets = await io.in(roomName).fetchSockets();
    io.to(roomName).emit('quiz:presence', {
        topic: normalizedTopic,
        activeParticipants: sockets.length
    });
};

const getLeaderboardPayload = async (topic) => {
    const normalizedTopic = normalizeTopic(topic);
    if (!normalizedTopic) {
        return null;
    }

    const cacheKey = `leaderboard:${normalizedTopic}`;
    const cachedLeaderboard = await getCachedJson(cacheKey);
    if (cachedLeaderboard) {
        return {
            topic: normalizedTopic,
            leaderboard: cachedLeaderboard
        };
    }

    const leaderboard = await buildLeaderboard(normalizedTopic);
    await setCachedJson(cacheKey, leaderboard, LEADERBOARD_CACHE_TTL_SECONDS);

    return {
        topic: normalizedTopic,
        leaderboard
    };
};

const emitLiveSessionState = async (roomId) => {
    if (!io) {
        return;
    }

    const roomName = getLiveRoom(roomId);
    const [meta, state, sockets] = await Promise.all([
        getLiveRoomMeta(roomId),
        buildLiveSessionState(roomId),
        io.in(roomName).fetchSockets()
    ]);

    if (!meta?.roomId || !state || !sockets.length) {
        return;
    }

    sockets.forEach((socketRef) => {
        io.to(socketRef.id).emit('quiz:session-state', {
            ...state,
            isHost: meta.hostSocketId === socketRef.id
        });
    });
};

const emitLiveLeaderboard = async (roomId, activity = null) => {
    if (!io) {
        return;
    }

    const meta = await getLiveRoomMeta(roomId);
    if (!meta?.roomId) {
        return;
    }

    const leaderboard = await getLiveRoomLeaderboard(roomId);
    io.to(getLiveRoom(roomId)).emit('quiz:room-leaderboard', {
        roomId,
        topic: meta.topic,
        leaderboard,
        activity
    });
};

const emitLiveSnapshot = async (roomId, activity = null) => {
    await Promise.all([
        emitLiveSessionState(roomId),
        emitLiveLeaderboard(roomId, activity)
    ]);
};

const syncLiveRoomTimer = async (roomId) => {
    const meta = await getLiveRoomMeta(roomId);
    if (!meta?.roomId) {
        await deleteLiveRoomIfExpired(roomId);
        return;
    }

    if (meta.status !== 'in_progress') {
        return;
    }

    const state = await buildLiveSessionState(roomId);
    if (!state) {
        await deleteLiveRoomIfExpired(roomId);
        return;
    }

    if (state.remainingSeconds <= 0) {
        const acquiredAdvanceLock = await acquireLiveRoomLock(
            liveRoomKeys.lockAdvance(roomId),
            LIVE_ROOM_ADVANCE_LOCK_MS
        );

        if (!acquiredAdvanceLock) {
            return;
        }

        await advanceLiveRoomQuestion(roomId);
        await emitLiveSnapshot(roomId);
        return;
    }

    const acquiredTickLock = await acquireLiveRoomLock(
        liveRoomKeys.lockTick(roomId),
        LIVE_ROOM_TICK_LOCK_MS
    );

    if (acquiredTickLock) {
        await emitLiveSessionState(roomId);
    }
};

const startRoomTimerPoller = () => {
    if (roomTimerPoller || !isRedisReady()) {
        return;
    }

    roomTimerPoller = setInterval(async () => {
        try {
            const activeRoomIds = await getActiveTimedRooms();
            await Promise.all(activeRoomIds.map(async (roomId) => {
                try {
                    await syncLiveRoomTimer(roomId);
                } catch (error) {
                    logger.warn(`Live room timer sync skipped for ${roomId}: ${error.message}`);
                }
            }));
        } catch (error) {
            logger.warn(`Live room timer poller skipped: ${error.message}`);
        }
    }, LIVE_ROOM_TICK_INTERVAL_MS);
};

const initializeRedisAdapter = async () => {
    if (!io || redisAdapterInitialized) {
        return;
    }

    const redisClient = await connectRedis();
    if (!redisClient || !isRedisReady()) {
        logger.warn('Socket.IO Redis adapter unavailable: Redis is not connected.');
        return;
    }

    try {
        redisPubClient = createRedisDuplicate();
        redisSubClient = createRedisDuplicate();

        if (!redisPubClient || !redisSubClient) {
            throw new Error('Redis duplicate clients could not be created.');
        }

        await Promise.all([
            redisPubClient.connect(),
            redisSubClient.connect()
        ]);

        io.adapter(createAdapter(redisPubClient, redisSubClient));
        redisAdapterInitialized = true;
        startRoomTimerPoller();
        logger.info('Socket.IO Redis adapter enabled');
    } catch (error) {
        logger.warn(`Socket.IO Redis adapter unavailable: ${error.message}`);
        startRoomTimerPoller();
    }
};

const generateUniqueRoomId = async () => {
    for (let attempt = 0; attempt < ROOM_ID_ATTEMPTS; attempt += 1) {
        const roomId = createRoomId();
        const existingRoom = await getLiveRoomMeta(roomId);
        if (!existingRoom) {
            return roomId;
        }
    }

    throw new Error('Unable to allocate a unique live room code right now.');
};

const leaveCurrentLiveRoom = async (socket, explicitRoomId = null) => {
    const roomId = String(explicitRoomId || socket.data.liveRoomId || '').trim().toUpperCase();
    if (!roomId) {
        socket.data.liveRoomId = null;
        return;
    }

    socket.leave(getLiveRoom(roomId));
    socket.data.liveRoomId = null;

    const result = await removeLiveParticipant(roomId, socket.id);
    if (!result) {
        await deleteLiveRoomIfExpired(roomId);
        return;
    }

    const meta = await getLiveRoomMeta(roomId);
    if (meta?.roomId && result.remainingParticipants > 0) {
        await emitLiveSnapshot(roomId);
    } else {
        await deleteLiveRoomIfExpired(roomId);
    }
};

export const emitTopicLeaderboardUpdate = async (topic, activity = null) => {
    if (!io) {
        return;
    }

    const payload = await getLeaderboardPayload(topic);
    if (!payload) {
        return;
    }

    io.to(getTopicRoom(payload.topic)).emit('quiz:leaderboard-update', {
        ...payload,
        activity
    });
};

export const initializeSocketServer = (httpServer, corsOrigins) => {
    io = new Server(httpServer, {
        cors: {
            origin: corsOrigins,
            credentials: true,
            methods: ['GET', 'POST']
        }
    });

    initializeRedisAdapter().catch((error) => {
        logger.warn(`Socket.IO Redis bootstrap skipped: ${error.message}`);
    });

    io.on('connection', (socket) => {
        socket.on('quiz:join-topic', async ({ topic, userName }) => {
            const normalizedTopic = normalizeTopic(topic);
            if (!normalizedTopic) {
                socket.emit('quiz:error', { message: 'Invalid topic room.' });
                return;
            }

            const nextRoom = getTopicRoom(normalizedTopic);
            const previousTopic = socket.data.topic;
            if (previousTopic) {
                socket.leave(getTopicRoom(previousTopic));
            }

            socket.data.topic = normalizedTopic;
            socket.data.userName = typeof userName === 'string' ? userName.trim() : socket.data.userName;
            socket.join(nextRoom);

            emitPresence(normalizedTopic);

            const leaderboardPayload = await getLeaderboardPayload(normalizedTopic);
            if (leaderboardPayload) {
                socket.emit('quiz:leaderboard-update', leaderboardPayload);
            }
        });

        socket.on('quiz:leave-topic', ({ topic }) => {
            const normalizedTopic = normalizeTopic(topic || socket.data.topic);
            if (!normalizedTopic) {
                return;
            }

            socket.leave(getTopicRoom(normalizedTopic));
            if (socket.data.topic === normalizedTopic) {
                socket.data.topic = null;
            }
            emitPresence(normalizedTopic);
        });

        socket.on('quiz:create-room', async ({ topic, difficulty, userName }, callback) => {
            const normalizedTopic = normalizeTopic(topic);
            const normalizedDifficulty = normalizeDifficulty(difficulty) || 'medium';

            if (!normalizedTopic) {
                callback?.({ ok: false, error: 'Invalid topic for live room.' });
                return;
            }

            try {
                if (socket.data.liveRoomId) {
                    await leaveCurrentLiveRoom(socket);
                }

                const result = await getHybridQuestions({
                    topic: normalizedTopic,
                    difficulty: normalizedDifficulty,
                    limit: LIVE_ROOM_QUESTION_LIMIT
                });

                const roomId = await generateUniqueRoomId();
                const hostName = (userName || '').trim() || `Host-${socket.id.slice(-4)}`;

                await createLiveRoomSession({
                    roomId,
                    topic: normalizedTopic,
                    difficulty: normalizedDifficulty,
                    hostSocketId: socket.id,
                    hostName,
                    questionDurationMs: LIVE_ROOM_QUESTION_DURATION_MS,
                    questions: result.questions
                });

                const participantName = await addLiveParticipant(roomId, socket.id, hostName);
                socket.data.liveRoomId = roomId;
                socket.data.userName = participantName;
                socket.join(getLiveRoom(roomId));

                await emitLiveSnapshot(roomId);
                callback?.({
                    ok: true,
                    roomId,
                    state: await buildLiveSessionState(roomId, socket.id)
                });
            } catch (error) {
                callback?.({ ok: false, error: error.message || 'Failed to create live room.' });
            }
        });

        socket.on('quiz:join-room', async ({ roomId, userName }, callback) => {
            const normalizedRoomId = String(roomId || '').trim().toUpperCase();
            if (!normalizedRoomId) {
                callback?.({ ok: false, error: 'Live room not found.' });
                return;
            }

            try {
                const session = await getLiveRoomMeta(normalizedRoomId);
                if (!session) {
                    callback?.({ ok: false, error: 'Live room not found.' });
                    return;
                }

                if (socket.data.liveRoomId) {
                    await leaveCurrentLiveRoom(socket);
                }

                const participantName = await addLiveParticipant(normalizedRoomId, socket.id, userName);
                socket.data.liveRoomId = normalizedRoomId;
                socket.data.userName = participantName;
                socket.join(getLiveRoom(normalizedRoomId));

                await emitLiveSnapshot(normalizedRoomId);
                callback?.({
                    ok: true,
                    roomId: normalizedRoomId,
                    state: await buildLiveSessionState(normalizedRoomId, socket.id)
                });
            } catch (error) {
                callback?.({ ok: false, error: error.message || 'Unable to join live room.' });
            }
        });

        socket.on('quiz:start-room', async ({ roomId }, callback) => {
            const normalizedRoomId = String(roomId || '').trim().toUpperCase();

            try {
                const session = await getLiveRoomMeta(normalizedRoomId);
                if (!session) {
                    callback?.({ ok: false, error: 'Live room not found.' });
                    return;
                }

                if (session.hostSocketId !== socket.id) {
                    callback?.({ ok: false, error: 'Only the host can start this room.' });
                    return;
                }

                if (session.status !== 'waiting') {
                    callback?.({ ok: false, error: 'Room is already in progress or completed.' });
                    return;
                }

                await startLiveRoom(normalizedRoomId);
                await emitLiveSnapshot(normalizedRoomId);
                callback?.({ ok: true });
            } catch (error) {
                callback?.({ ok: false, error: error.message || 'Unable to start live room.' });
            }
        });

        socket.on('quiz:submit-answer', async ({ roomId, questionIndex, selectedOption }, callback) => {
            const normalizedRoomId = String(roomId || '').trim().toUpperCase();

            try {
                const result = await submitLiveAnswer({
                    roomId: normalizedRoomId,
                    socketId: socket.id,
                    questionIndex,
                    selectedOption
                });

                await emitLiveLeaderboard(normalizedRoomId, {
                    roomId: normalizedRoomId,
                    userName: socket.data.userName,
                    questionIndex,
                    isCorrect: result.isCorrect
                });

                callback?.({ ok: true, isCorrect: result.isCorrect });
            } catch (error) {
                callback?.({ ok: false, error: error.message || 'Live answer rejected.' });
            }
        });

        socket.on('quiz:next-question', async ({ roomId }, callback) => {
            const normalizedRoomId = String(roomId || '').trim().toUpperCase();

            try {
                const session = await getLiveRoomMeta(normalizedRoomId);
                if (!session) {
                    callback?.({ ok: false, error: 'Live room not found.' });
                    return;
                }

                if (session.hostSocketId !== socket.id) {
                    callback?.({ ok: false, error: 'Only the host can advance this room.' });
                    return;
                }

                const acquiredAdvanceLock = await acquireLiveRoomLock(
                    liveRoomKeys.lockAdvance(normalizedRoomId),
                    LIVE_ROOM_ADVANCE_LOCK_MS
                );

                if (!acquiredAdvanceLock) {
                    callback?.({ ok: false, error: 'Live room is already advancing.' });
                    return;
                }

                await advanceLiveRoomQuestion(normalizedRoomId);
                await emitLiveSnapshot(normalizedRoomId);
                callback?.({ ok: true });
            } catch (error) {
                callback?.({ ok: false, error: error.message || 'Unable to advance live room.' });
            }
        });

        socket.on('quiz:end-room', async ({ roomId }, callback) => {
            const normalizedRoomId = String(roomId || '').trim().toUpperCase();

            try {
                const session = await getLiveRoomMeta(normalizedRoomId);
                if (!session) {
                    callback?.({ ok: false, error: 'Live room not found.' });
                    return;
                }

                if (session.hostSocketId !== socket.id) {
                    callback?.({ ok: false, error: 'Only the host can end this room.' });
                    return;
                }

                await completeLiveRoom(normalizedRoomId);
                await emitLiveSnapshot(normalizedRoomId);
                callback?.({ ok: true });
            } catch (error) {
                callback?.({ ok: false, error: error.message || 'Unable to end live room.' });
            }
        });

        socket.on('quiz:leave-room', async ({ roomId }) => {
            const normalizedRoomId = String(roomId || socket.data.liveRoomId || '').trim().toUpperCase();
            if (!normalizedRoomId) {
                return;
            }

            try {
                await leaveCurrentLiveRoom(socket, normalizedRoomId);
            } catch (error) {
                socket.emit('quiz:error', { message: error.message || 'Unable to leave live room.' });
            }
        });

        socket.on('disconnect', () => {
            if (socket.data.topic) {
                emitPresence(socket.data.topic);
            }

            if (socket.data.liveRoomId) {
                leaveCurrentLiveRoom(socket).catch((error) => {
                    logger.warn(`Live room disconnect cleanup skipped: ${error.message}`);
                });
            }
        });
    });

    return io;
};

export const getSocketServer = () => io;

export const getSocketServerStatus = () => ({
    initialized: Boolean(io),
    redisAdapterEnabled: redisAdapterInitialized,
    roomTimerPollerActive: Boolean(roomTimerPoller)
});
