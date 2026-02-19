import mongoose from 'mongoose';

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
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to MongoDB');
        return true;
    } catch (err) {
        console.error('MongoDB connection error:', err.message);

        // Provide helpful error messages
        if (err.message.includes('ENOTFOUND')) {
            console.error('   This usually means:');
            console.error('   1. Your MongoDB server is not running');
            console.error('   2. Your connection string has incorrect hostname/port');
            console.error('   3. Your network connection is down');
        } else if (err.message.includes('auth failed')) {
            console.error('   Authentication failed - check your username/password');
        } else if (err.message.includes('Invalid MONGO_URI')) {
            console.error('   Please check your MONGO_URI in the .env file');
        }

        const allowWithoutDb = process.env.REQUIRE_DB_ON_START !== 'true';

        if (allowWithoutDb) {
            console.warn('Starting server without MongoDB connection (limited functionality).');
            return false;
        }

        process.exit(1);
    }
};

export default connectDB;
