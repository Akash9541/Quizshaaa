import mongoose from 'mongoose';

const quizHistorySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    topic: {
        type: String,
        required: true,
        enum: [
            'Logical Reasoning',
            'Coding & Problem-Solving',
            'Quantitative Aptitude',
            'CS Fundamentals',
            'Verbal & Communication',
            'Mock Tests & Assessments'
        ]
    },
    score: {
        type: Number,
        required: true
    },
    totalQuestions: {
        type: Number,
        required: true
    },
    percentage: {
        type: Number
    },
    correctAnswers: {
        type: Number
    },
    incorrectAnswers: {
        type: Number
    },
    dateTaken: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

quizHistorySchema.pre('save', function (next) {
    if (this.isNew) {
        this.percentage = Math.round((this.score / this.totalQuestions) * 100);
        this.correctAnswers = this.score;
        this.incorrectAnswers = this.totalQuestions - this.score;
    }
    next();
});

const QuizHistory = mongoose.model("QuizHistory", quizHistorySchema);
export default QuizHistory;
