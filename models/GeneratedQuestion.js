import mongoose from 'mongoose';

const generatedQuestionSchema = new mongoose.Schema({
    topic: {
        type: String,
        required: true,
        index: true
    },
    difficulty: {
        type: String,
        required: true,
        enum: ['easy', 'medium', 'hard'],
        index: true
    },
    question: {
        type: String,
        required: true
    },
    options: {
        type: [String],
        required: true,
        validate: {
            validator: (value) => Array.isArray(value) && value.length >= 4,
            message: 'Each quiz question must contain at least four options.'
        }
    },
    answer: {
        type: String,
        required: true
    },
    explanation: {
        type: String,
        default: ''
    },
    source: {
        type: String,
        enum: ['ai', 'seed'],
        default: 'ai'
    },
    provider: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

generatedQuestionSchema.index({ topic: 1, difficulty: 1, createdAt: -1 });

const GeneratedQuestion = mongoose.model('GeneratedQuestion', generatedQuestionSchema);

export default GeneratedQuestion;
