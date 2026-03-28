import mongoose from 'mongoose';
import { logger } from '../services/logger.js';

const connectDB = async () => {
    try {
        // Check if MONGO_URI is set
        if (!process.env.MONGO_URI) {
            throw new Error('MONGO_URI environment variable is not defined');
        }

        // Check if the connection string looks valid
        if (!process.env.MONGO_URI.startsWith('mongodb')) {
            throw new Error('Invalid MONGO_URI format. Must start with mongodb:// or mongodb+srv://');
        }

        mongoose.set('strictQuery', true);
        await mongoose.connect(process.env.MONGO_URI, {
            serverSelectionTimeoutMS: 5000
        });
        logger.info('Connected to MongoDB');
        return true;
    } catch (err) {
        logger.error(`MongoDB connection error: ${err.message}`);

        // Provide helpful error messages
        if (err.message.includes('ENOTFOUND')) {
            logger.error('MongoDB hostname could not be resolved. Check that MongoDB is running and the host/port are correct.');
        } else if (err.message.includes('auth failed')) {
            logger.error('MongoDB authentication failed. Check your username and password.');
        } else if (err.message.includes('Invalid MONGO_URI')) {
            logger.error('Please check your MONGO_URI in the .env file.');
        }

        const allowWithoutDb = process.env.REQUIRE_DB_ON_START !== 'true';

        if (allowWithoutDb) {
            logger.warn('Starting server without MongoDB connection (limited functionality).');
            return false;
        }

        process.exit(1);
    }
};

export default connectDB;
