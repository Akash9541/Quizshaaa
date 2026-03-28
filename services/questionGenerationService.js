import mongoose from 'mongoose';

import GeneratedQuestion from '../models/GeneratedQuestion.js';
import { SEED_QUESTION_BANK } from '../data/seedQuestions.js';
import { getCachedJson, setCachedJson } from './cacheService.js';
import { generateQuestionsWithGemini } from './geminiQuestionService.js';
import { logger } from './logger.js';
import { normalizeDifficulty, normalizeTopic } from '../utils/quizTopics.js';

const inFlightHybridQuestionRequests = new Map();
const QUESTION_CACHE_TTL_SECONDS = 10 * 60;

const shuffle = (items) => [...items].sort(() => Math.random() - 0.5);

const uniqueByQuestion = (questions) => {
    const seen = new Set();
    return questions.filter((question) => {
        const key = question.question.trim().toLowerCase();
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
};

const canUseDatabase = () => mongoose.connection.readyState === 1;

const loadQuestionsFromDatabase = async ({ topic, difficulty, limit }) => {
    if (!canUseDatabase()) {
        return [];
    }

    return GeneratedQuestion.aggregate([
        {
            $match: {
                topic,
                difficulty
            }
        },
        {
            $sample: {
                size: limit
            }
        }
    ]);
};

const saveGeneratedQuestions = async (questions) => {
    if (!questions.length || !canUseDatabase()) {
        return;
    }

    try {
        await GeneratedQuestion.insertMany(questions, {
            ordered: false
        });
    } catch (error) {
        logger.warn(`Generated question persistence skipped: ${error.message}`);
    }
};

const loadSeedQuestions = ({ topic, difficulty, limit }) => {
    const topicBank = SEED_QUESTION_BANK[topic] || [];
    const exactMatch = topicBank.filter((question) => question.difficulty === difficulty);
    const fallback = topicBank.filter((question) => question.difficulty !== difficulty);

    return shuffle([...exactMatch, ...fallback])
        .slice(0, limit)
        .map((question) => ({
            topic,
            difficulty: question.difficulty,
            question: question.question,
            options: question.options,
            answer: question.answer,
            explanation: question.explanation,
            source: 'seed',
            provider: 'local-seed'
        }));
};

const formatQuestionsForResponse = (questions) => questions.map((question) => ({
    id: question._id?.toString?.() || question.question,
    topic: question.topic,
    difficulty: question.difficulty,
    question: question.question,
    options: question.options,
    answer: question.answer,
    explanation: question.explanation,
    source: question.source
}));

const buildRequestKey = ({ topic, difficulty, limit }) => `${topic}::${difficulty}::${limit}`;

const buildHybridQuestions = async ({ topic, difficulty = 'medium', limit = 5 }) => {
    const normalizedTopic = normalizeTopic(topic);
    const normalizedDifficulty = normalizeDifficulty(difficulty);
    const normalizedLimit = Math.max(3, Math.min(Number(limit) || 5, 10));

    if (!normalizedTopic) {
        throw new Error('Invalid topic');
    }

    if (!normalizedDifficulty) {
        throw new Error('Invalid difficulty');
    }

    const cachedQuestions = await loadQuestionsFromDatabase({
        topic: normalizedTopic,
        difficulty: normalizedDifficulty,
        limit: normalizedLimit
    });

    let fallbackReason = '';

    if (cachedQuestions.length >= normalizedLimit) {
        return {
            source: 'database',
            fallbackReason,
            questions: formatQuestionsForResponse(cachedQuestions)
        };
    }

    const missingCount = normalizedLimit - cachedQuestions.length;
    let aiQuestions = [];

    if (missingCount > 0) {
        if (!process.env.GEMINI_API_KEY) {
            fallbackReason = 'GEMINI_API_KEY is not loaded in the backend process. Restart the backend after updating backend/.env.';
        } else {
            try {
                aiQuestions = await generateQuestionsWithGemini({
                    topic: normalizedTopic,
                    difficulty: normalizedDifficulty,
                    limit: missingCount
                });
            } catch (error) {
                fallbackReason = error.message;
                logger.warn(`Gemini generation failed: ${error.message}`);
            }
        }
    }

    if (aiQuestions.length) {
        await saveGeneratedQuestions(aiQuestions);
    }

    const seedQuestions = loadSeedQuestions({
        topic: normalizedTopic,
        difficulty: normalizedDifficulty,
        limit: normalizedLimit
    });

    const mergedQuestions = uniqueByQuestion([
        ...cachedQuestions,
        ...aiQuestions,
        ...seedQuestions
    ]).slice(0, normalizedLimit);

    const source = aiQuestions.length
        ? 'ai'
        : cachedQuestions.length
            ? 'database+seed'
            : 'seed';

    return {
        source,
        fallbackReason,
        questions: formatQuestionsForResponse(mergedQuestions)
    };
};

export const getHybridQuestions = async ({ topic, difficulty = 'medium', limit = 5 }) => {
    const normalizedTopic = normalizeTopic(topic);
    const normalizedDifficulty = normalizeDifficulty(difficulty);
    const normalizedLimit = Math.max(3, Math.min(Number(limit) || 5, 10));

    if (!normalizedTopic) {
        throw new Error('Invalid topic');
    }

    if (!normalizedDifficulty) {
        throw new Error('Invalid difficulty');
    }

    const cacheKey = `questions:${normalizedTopic}:${normalizedDifficulty}:${normalizedLimit}`;
    const cachedPayload = await getCachedJson(cacheKey);
    if (cachedPayload) {
        return cachedPayload;
    }

    const requestKey = buildRequestKey({
        topic: normalizedTopic,
        difficulty: normalizedDifficulty,
        limit: normalizedLimit
    });

    if (inFlightHybridQuestionRequests.has(requestKey)) {
        return inFlightHybridQuestionRequests.get(requestKey);
    }

    const requestPromise = buildHybridQuestions({
        topic: normalizedTopic,
        difficulty: normalizedDifficulty,
        limit: normalizedLimit
    });

    inFlightHybridQuestionRequests.set(requestKey, requestPromise);

    try {
        const result = await requestPromise;
        await setCachedJson(cacheKey, result, QUESTION_CACHE_TTL_SECONDS);
        return result;
    } finally {
        if (inFlightHybridQuestionRequests.get(requestKey) === requestPromise) {
            inFlightHybridQuestionRequests.delete(requestKey);
        }
    }
};
