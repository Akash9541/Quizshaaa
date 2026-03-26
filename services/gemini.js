import { GoogleGenerativeAI } from '@google/generative-ai';

const DEFAULT_GEMINI_MODEL = 'gemini-2.5-flash';

const normalizeModelName = (modelName) => String(modelName || '')
    .trim()
    .replace(/^models\//, '');

export const GEMINI_MODEL = normalizeModelName(
    process.env.GEMINI_MODEL || DEFAULT_GEMINI_MODEL
);

const genAI = process.env.GEMINI_API_KEY
    ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
    : null;

export const getGeminiModel = (modelName = GEMINI_MODEL) => {
    if (!genAI) {
        throw new Error('GEMINI_API_KEY is not configured');
    }

    return genAI.getGenerativeModel({
        model: normalizeModelName(modelName)
    });
};

export const getGeminiModelCandidates = () => {
    const fallbackModel = normalizeModelName(
        process.env.GEMINI_FALLBACK_MODEL || DEFAULT_GEMINI_MODEL
    );

    return [...new Set([GEMINI_MODEL, fallbackModel].filter(Boolean))];
};
