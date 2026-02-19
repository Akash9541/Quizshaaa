import QuizHistory from '../models/QuizHistory.js';

const VALID_TOPICS = new Set([
    'Logical Reasoning',
    'Coding & Problem-Solving',
    'Quantitative Aptitude',
    'CS Fundamentals',
    'Verbal & Communication',
    'Mock Tests & Assessments'
]);

const TOPIC_ALIASES = {
    'logical reasoning quiz': 'Logical Reasoning',
    'logical reasoning': 'Logical Reasoning',
    'coding & problem-solving': 'Coding & Problem-Solving',
    'coding and problem-solving': 'Coding & Problem-Solving',
    'quantitative aptitude quiz': 'Quantitative Aptitude',
    'quantitative aptitude': 'Quantitative Aptitude',
    'cs fundamentals quiz': 'CS Fundamentals',
    'cs fundamentals': 'CS Fundamentals',
    'verbal ability': 'Verbal & Communication',
    'verbal & communication': 'Verbal & Communication',
    'mock test': 'Mock Tests & Assessments',
    'mock tests & assessments': 'Mock Tests & Assessments'
};

const normalizeTopic = (value) => {
    if (!value || typeof value !== 'string') {
        return null;
    }
    if (VALID_TOPICS.has(value)) {
        return value;
    }
    const normalizedKey = value.trim().toLowerCase();
    return TOPIC_ALIASES[normalizedKey] || null;
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
        res.status(201).json({ message: "History saved", history });
    } catch (error) {
        console.error("Save history error:", error);
        res.status(500).json({ error: "Failed to save history" });
    }
};

export const getQuizHistory = async (req, res) => {
    try {
        const history = await QuizHistory.find({ userId: req.user.userId }).sort({ dateTaken: -1 });
        res.json(history);
    } catch (error) {
        console.error("Fetch history error:", error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
};

export const getLeaderboard = async (req, res) => {
    const { topic } = req.params;
    const normalizedTopic = normalizeTopic(topic);
    if (!normalizedTopic) return res.status(400).json({ error: "Invalid topic" });
    try {
        const leaderboard = await QuizHistory.aggregate([
            { $match: { topic: normalizedTopic } },
            { $lookup: { from: "users", localField: "userId", foreignField: "_id", as: "user" } },
            { $unwind: "$user" },
            { $project: { _id: 1, score: 1, totalQuestions: 1, percentage: 1, dateTaken: 1, username: "$user.name" } },
            { $sort: { score: -1, percentage: -1, dateTaken: 1 } },
            { $limit: 50 }
        ]);
        res.json(leaderboard);
    } catch (error) {
        console.error("Leaderboard error:", error);
        res.status(500).json({ error: "Failed to load leaderboard" });
    }
};

export const getDashboardStats = async (req, res) => {
    try {
        const userId = req.user.userId;
        const history = await QuizHistory.find({ userId });
        if (history.length === 0) return res.json({
            totalQuizzes: 0,
            bestScore: 0,
            averageScore: 0,
            topics: [],
            completionRate: 0
        });

        const totalQuizzes = history.length;
        const bestScore = Math.max(...history.map(h => h.score));
        const totalPossible = history.reduce((sum, h) => sum + h.totalQuestions, 0);
        const totalCorrect = history.reduce((sum, h) => sum + h.score, 0);
        const averageScore = Math.round((totalCorrect / totalPossible) * 100);
        const topics = [...new Set(history.map(h => h.topic))];
        const badges = [];
        if (bestScore >= 45) badges.push("Quiz Master");
        if (averageScore >= 80) badges.push("Top Performer");
        if (totalQuizzes >= 10) badges.push("Marathon Learner");

        res.json({
            totalQuizzes,
            bestScore,
            averageScore,
            topics,
            badges,
            lastActivity: history[0]?.dateTaken
        });
    } catch (error) {
        console.error("Dashboard error:", error);
        res.status(500).json({ error: "Failed to load dashboard" });
    }
};

export const getRecentQuizzes = async (req, res) => { // Added missing endpoint
    try {
        const userId = req.user.userId;
        const history = await QuizHistory.find({ userId }).sort({ dateTaken: -1 }).limit(5);

        const quizzes = history.map(h => ({
            category: h.topic,
            date: h.dateTaken,
            score: h.percentage,
            correctAnswers: h.correctAnswers,
            totalQuestions: h.totalQuestions
        }));

        res.json({ quizzes });
    } catch (error) {
        console.error("Recent quizzes error:", error);
        res.status(500).json({ error: "Failed to load recent quizzes" });
    }
};

export const getUserStats = async (req, res) => { // Added handler for /stats
    try {
        const userId = req.user.userId;
        const history = await QuizHistory.find({ userId });
        if (history.length === 0) return res.json({
            quizzesCompleted: 0,
            averageScore: 0,
            totalPoints: 0
        });

        const quizzesCompleted = history.length;
        const totalPossible = history.reduce((sum, h) => sum + h.totalQuestions, 0);
        const totalCorrect = history.reduce((sum, h) => sum + h.score, 0);
        const averageScore = Math.round((totalCorrect / totalPossible) * 100);
        const totalPoints = totalCorrect * 10; // Assuming 10 points per correct answer

        res.json({
            quizzesCompleted,
            averageScore,
            totalPoints
        });
    } catch (error) {
        console.error("User stats error:", error);
        res.status(500).json({ error: "Failed to load user stats" });
    }
}
