import { getGeminiModel, getGeminiModelCandidates } from './gemini.js';
import { logger } from './logger.js';
import { registerGeminiCooldown, scheduleGeminiRequest } from './geminiScheduler.js';
import { normalizeDifficulty, normalizeTopic } from '../utils/quizTopics.js';

const DEFAULT_MAX_429_RETRIES = Math.max(Number(process.env.GEMINI_MAX_429_RETRIES || 2), 0);
const DEFAULT_RETRY_DELAY_MS = Math.max(Number(process.env.GEMINI_DEFAULT_RETRY_DELAY_MS || 60_000), 1000);
const DEFAULT_RETRY_JITTER_MS = Math.max(Number(process.env.GEMINI_RETRY_JITTER_MS || 1500), 0);

const buildPrompt = ({ topic, difficulty, limit }) => `
Generate ${limit} placement-preparation multiple-choice quiz questions for the topic "${topic}" at ${difficulty} difficulty.

Each question must have exactly 4 options.

Return valid JSON only in this exact format, with no markdown and no extra text:
{
  "questions": [
    {
      "question": "string",
      "options": ["string", "string", "string", "string"],
      "correctAnswer": "one of the options exactly",
      "explanation": "short explanation"
    }
  ]
}

Rules:
- No markdown fences
- Exactly 4 options per question
- Keep questions placement-prep focused
- Avoid duplicates
- Keep explanations under 25 words
`.trim();

const extractJsonPayload = (rawText) => {
    const withoutFences = rawText.replace(/```json|```/gi, '').trim();
    const start = withoutFences.indexOf('{');
    const end = withoutFences.lastIndexOf('}');

    if (start === -1 || end === -1 || end < start) {
        throw new Error('Gemini response did not contain a JSON object.');
    }

    return withoutFences.slice(start, end + 1);
};

const parseRetryDelayMs = (error) => {
    const retryDelay = error?.errorDetails?.find?.(
        (detail) => detail?.['@type'] === 'type.googleapis.com/google.rpc.RetryInfo'
    )?.retryDelay;

    if (typeof retryDelay === 'string') {
        const match = retryDelay.match(/([\d.]+)s/);
        if (match) {
            return Math.ceil(Number(match[1]) * 1000);
        }
    }

    const retryMatch = String(error?.message || '').match(/Please retry in\s+([\d.]+)s/i);
    if (retryMatch) {
        return Math.ceil(Number(retryMatch[1]) * 1000);
    }

    return DEFAULT_RETRY_DELAY_MS;
};

const calculateRetryJitterMs = (attempt) => {
    if (!DEFAULT_RETRY_JITTER_MS) {
        return 0;
    }

    const spread = DEFAULT_RETRY_JITTER_MS * Math.max(attempt + 1, 1);
    return Math.floor(Math.random() * spread);
};

const summarizeGeminiError = (error, modelName) => {
    const status = error?.status;
    const message = error?.message || 'Unknown Gemini error';

    if (status === 429) {
        const retryMatch = message.match(/Please retry in\s+([\d.]+s?)/i);
        const retryText = retryMatch ? ` Retry after about ${retryMatch[1]}.` : '';
        return `Gemini quota exceeded for model "${modelName}". Your API key is valid, but this project has no available request/token quota right now.${retryText}`;
    }

    return `Gemini request failed for model "${modelName}": ${status || 'unknown'} ${message}`;
};

const sanitizeAiQuestions = (questions, { topic, difficulty, provider }) => {
    if (!Array.isArray(questions)) {
        return [];
    }

    return questions
        .map((question) => {
            const prompt = typeof question?.question === 'string' ? question.question.trim() : '';
            const options = Array.isArray(question?.options)
                ? question.options.map((option) => String(option).trim()).filter(Boolean)
                : [];
            const answer = typeof question?.answer === 'string' ? question.answer.trim() : '';
            const correctAnswer = typeof question?.correctAnswer === 'string' ? question.correctAnswer.trim() : '';
            const explanation = typeof question?.explanation === 'string' ? question.explanation.trim() : '';
            const uniqueOptions = [...new Set(options)].slice(0, 4);
            const resolvedAnswer = correctAnswer || answer;

            if (!prompt || uniqueOptions.length < 4 || !resolvedAnswer || !uniqueOptions.includes(resolvedAnswer)) {
                return null;
            }

            return {
                topic,
                difficulty,
                question: prompt,
                options: uniqueOptions,
                answer: resolvedAnswer,
                explanation,
                source: 'ai',
                provider
            };
        })
        .filter(Boolean);
};

export const generateQuestionsWithGemini = async ({ topic, difficulty = 'medium', limit = 5 }) => {
    const normalizedTopic = normalizeTopic(topic);
    const normalizedDifficulty = normalizeDifficulty(difficulty);

    if (!normalizedTopic) {
        throw new Error('Invalid topic for Gemini generation.');
    }

    if (!normalizedDifficulty) {
        throw new Error('Invalid difficulty for Gemini generation.');
    }

    if (!process.env.GEMINI_API_KEY) {
        return [];
    }

    const modelCandidates = getGeminiModelCandidates();
    let lastError = null;

    for (const modelName of modelCandidates) {
        const model = getGeminiModel(modelName);

        for (let attempt = 0; attempt <= DEFAULT_MAX_429_RETRIES; attempt += 1) {
            try {
                const result = await scheduleGeminiRequest(() => model.generateContent(buildPrompt({
                    topic: normalizedTopic,
                    difficulty: normalizedDifficulty,
                    limit
                })));
                const rawText = result?.response?.text?.() || '';

                if (!rawText) {
                    lastError = `Gemini returned an empty response for model "${modelName}".`;
                    break;
                }

                const parsedPayload = JSON.parse(extractJsonPayload(rawText));
                const sanitized = sanitizeAiQuestions(parsedPayload?.questions, {
                    topic: normalizedTopic,
                    difficulty: normalizedDifficulty,
                    provider: modelName
                }).slice(0, limit);

                if (sanitized.length) {
                    return sanitized;
                }

                lastError = `Gemini returned unusable questions for model "${modelName}".`;
                break;
            } catch (error) {
                lastError = summarizeGeminiError(error, modelName);

                if (error?.status === 404) {
                    break;
                }

                if (error?.status === 429 && attempt < DEFAULT_MAX_429_RETRIES) {
                    const retryDelayMs = parseRetryDelayMs(error);
                    const jitterMs = calculateRetryJitterMs(attempt);
                    const coordinatedDelayMs = retryDelayMs + jitterMs;

                    registerGeminiCooldown(coordinatedDelayMs);
                    logger.warn(
                        `Gemini quota/rate limit hit for "${modelName}". Coordinated retry in ${coordinatedDelayMs}ms ` +
                        `(base ${retryDelayMs}ms + jitter ${jitterMs}ms, attempt ${attempt + 1}/${DEFAULT_MAX_429_RETRIES}).`
                    );
                    continue;
                }

                throw new Error(lastError);
            }
        }
    }

    throw new Error(lastError || `Gemini request failed for all candidate models: ${modelCandidates.join(', ')}`);
};
