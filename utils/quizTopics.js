export const QUIZ_TOPICS = [
    'Logical Reasoning',
    'Coding & Problem-Solving',
    'Quantitative Aptitude',
    'CS Fundamentals',
    'Verbal & Communication',
    'Mock Tests & Assessments'
];

export const QUIZ_DIFFICULTIES = ['easy', 'medium', 'hard'];

export const VALID_TOPICS = new Set(QUIZ_TOPICS);
export const VALID_DIFFICULTIES = new Set(QUIZ_DIFFICULTIES);

export const TOPIC_ALIASES = {
    'logical reasoning quiz': 'Logical Reasoning',
    'logical reasoning': 'Logical Reasoning',
    'coding & problem-solving': 'Coding & Problem-Solving',
    'coding and problem-solving': 'Coding & Problem-Solving',
    'coding': 'Coding & Problem-Solving',
    'quantitative aptitude quiz': 'Quantitative Aptitude',
    'quantitative aptitude': 'Quantitative Aptitude',
    'aptitude': 'Quantitative Aptitude',
    'cs fundamentals quiz': 'CS Fundamentals',
    'cs fundamentals': 'CS Fundamentals',
    'computer science fundamentals': 'CS Fundamentals',
    'verbal ability': 'Verbal & Communication',
    'verbal & communication': 'Verbal & Communication',
    'verbal': 'Verbal & Communication',
    'mock test': 'Mock Tests & Assessments',
    'mock tests & assessments': 'Mock Tests & Assessments',
    'mock tests': 'Mock Tests & Assessments'
};

export const normalizeTopic = (value) => {
    if (!value || typeof value !== 'string') {
        return null;
    }

    if (VALID_TOPICS.has(value)) {
        return value;
    }

    const normalizedKey = value.trim().toLowerCase();
    return TOPIC_ALIASES[normalizedKey] || null;
};

export const normalizeDifficulty = (value) => {
    if (!value || typeof value !== 'string') {
        return 'medium';
    }

    const normalized = value.trim().toLowerCase();
    return VALID_DIFFICULTIES.has(normalized) ? normalized : null;
};
