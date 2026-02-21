import otpGenerator from 'otp-generator';
import bcrypt from 'bcryptjs';
import Otp from '../models/Otp.js';
import { sendEmail } from '../services/emailService.js';

export const sendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail) {
            return res.status(400).json({ error: 'Email is required' });
        }

        // Check if user already exists (optional, depending on flow)
        // const user = await User.findOne({ email });
        // if (user) {
        //   return res.status(400).json({ error: 'User already exists' });
        // }

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
            'Your Verification OTP',
            `Your OTP is: ${otp}`,
            `<p>Your OTP is: <strong>${otp}</strong></p><p>This OTP is valid for 5 minutes.</p>`
        );

        res.status(200).json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Error sending OTP:', error);
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

        // OTP is valid - delete it so it can't be reused
        await Otp.deleteOne({ _id: otpRecord._id });

        // Mark user as verified or update some other state if needed?
        // For now we just return success, frontend can proceed to next step (e.g. registration or password reset)
        // If this is for email verification during signup, we might want to update the user record here or return a token.
        // Assuming this is part of a signup flow or a standalone verification step.

        // You might want to update the User model verification status here if used for signup
        // const user = await User.findOne({ email });
        // if (user) {
        //   user.isVerified = true;
        //   await user.save();
        // }

        res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
};
