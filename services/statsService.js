import QuizHistory from '../models/QuizHistory.js';
import { normalizeTopic } from '../utils/quizTopics.js';

export const buildDashboardStats = async (userId) => {
    const history = await QuizHistory.find({ userId }).sort({ dateTaken: -1 });
    if (history.length === 0) {
        return {
            totalQuizzes: 0,
            bestScore: 0,
            averageScore: 0,
            topics: [],
            completionRate: 0,
            badges: [],
            lastActivity: null
        };
    }

    const totalQuizzes = history.length;
    const bestScore = Math.max(...history.map((item) => item.score));
    const totalPossible = history.reduce((sum, item) => sum + item.totalQuestions, 0);
    const totalCorrect = history.reduce((sum, item) => sum + item.score, 0);
    const averageScore = totalPossible ? Math.round((totalCorrect / totalPossible) * 100) : 0;
    const topics = [...new Set(history.map((item) => item.topic))];
    const badges = [];

    if (bestScore >= 45) badges.push('Quiz Master');
    if (averageScore >= 80) badges.push('Top Performer');
    if (totalQuizzes >= 10) badges.push('Marathon Learner');

    return {
        totalQuizzes,
        bestScore,
        averageScore,
        topics,
        completionRate: 100,
        badges,
        lastActivity: history[0]?.dateTaken || null
    };
};

export const buildRecentQuizzes = async (userId) => {
    const history = await QuizHistory.find({ userId }).sort({ dateTaken: -1 }).limit(5);

    return {
        quizzes: history.map((item) => ({
            category: item.topic,
            date: item.dateTaken,
            score: item.percentage,
            correctAnswers: item.correctAnswers,
            totalQuestions: item.totalQuestions
        }))
    };
};

export const buildUserStats = async (userId) => {
    const history = await QuizHistory.find({ userId });
    if (history.length === 0) {
        return {
            quizzesCompleted: 0,
            averageScore: 0,
            totalPoints: 0
        };
    }

    const totalPossible = history.reduce((sum, item) => sum + item.totalQuestions, 0);
    const totalCorrect = history.reduce((sum, item) => sum + item.score, 0);

    return {
        quizzesCompleted: history.length,
        averageScore: totalPossible ? Math.round((totalCorrect / totalPossible) * 100) : 0,
        totalPoints: totalCorrect * 10
    };
};

export const buildLeaderboard = async (topic) => {
    const normalizedTopic = normalizeTopic(topic);
    if (!normalizedTopic) {
        return null;
    }

    return QuizHistory.aggregate([
        { $match: { topic: normalizedTopic } },
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'user' } },
        { $unwind: '$user' },
        { $project: { _id: 1, score: 1, totalQuestions: 1, percentage: 1, dateTaken: 1, username: '$user.name' } },
        { $sort: { score: -1, percentage: -1, dateTaken: 1 } },
        { $limit: 50 }
    ]);
};
