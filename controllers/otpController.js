import otpGenerator from 'otp-generator';
import bcrypt from 'bcryptjs';
import Otp from '../models/Otp.js';
import User from '../models/User.js';
import { sendEmail } from '../services/emailService.js';
import { logger } from '../services/logger.js';

export const sendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(404).json({ error: 'No account found with this email' });
        }

        // Generate OTP
        const otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            specialChars: false,
            lowerCaseAlphabets: false,
        });

        // Hash OTP
        const salt = await bcrypt.genSalt(10);
        const hashedOtp = await bcrypt.hash(otp, salt);

        // Save to DB (overwrite existing OTP for this email)
        await Otp.deleteMany({ email: normalizedEmail }); // Delete any existing OTPs for this email
        const newOtp = new Otp({ email: normalizedEmail, otp: hashedOtp });
        await newOtp.save();

        // Send Email
        await sendEmail(
            normalizedEmail,
            'Your Quizshaala password reset OTP',
            `Your Quizshaala password reset OTP is: ${otp}`,
            `<p>Your Quizshaala password reset OTP is: <strong>${otp}</strong></p><p>This OTP is valid for 5 minutes.</p>`
        );

        res.status(200).json({ message: 'OTP sent successfully' });
    } catch (error) {
        logger.error('Error sending OTP', { error: error.message });
        res.status(500).json({
            error: error?.message || 'Failed to send OTP'
        });
    }
};

export const verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        // Find the most recent OTP for this email
        const otpRecord = await Otp.findOne({ email: normalizedEmail }).sort({ createdAt: -1 });

        if (!otpRecord) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // specific check: verify provided OTP with hashed OTP in DB
        const isValid = await bcrypt.compare(otp, otpRecord.otp);

        if (!isValid) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
        logger.error('Error verifying OTP', { error: error.message });
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
};

export const resetPassword = async (req, res) => {
    try {
        const { email, otp, password } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail || !otp || !password) {
            return res.status(400).json({ error: 'Email, OTP, and new password are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        const [user, otpRecord] = await Promise.all([
            User.findOne({ email: normalizedEmail }),
            Otp.findOne({ email: normalizedEmail }).sort({ createdAt: -1 })
        ]);

        if (!user) {
            return res.status(404).json({ error: 'No account found with this email' });
        }

        if (!otpRecord) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        const isValidOtp = await bcrypt.compare(otp, otpRecord.otp);
        if (!isValidOtp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        user.password = password;
        user.refreshToken = null;
        user.loginAttempts = 0;
        user.lockUntil = null;

        await Promise.all([
            user.save(),
            Otp.deleteMany({ email: normalizedEmail })
        ]);

        res.status(200).json({ message: 'Password reset successfully. Please log in with your new password.' });
    } catch (error) {
        logger.error('Reset password error', { error: error.message });
        res.status(500).json({ error: 'Failed to reset password' });
    }
};
