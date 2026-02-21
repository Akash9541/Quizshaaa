import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { generateOtp, sendEmail } from '../services/emailService.js';
dotenv.config();

const sendVerificationEmail = async (to, subject, html) => {
    await sendEmail(to, subject, 'Your OTP for Quizshaala verification', html);
};

const getClientSafeEmailError = (error, fallbackMessage) => error?.message || fallbackMessage;

export const signup = async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail || !password || !name) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        const existingUser = await User.findOne({ email: normalizedEmail });

        if (existingUser) {
            if (!existingUser.isVerified) {
                // User exists but NOT verified, resend OTP.
                const otp = generateOtp();
                const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

                existingUser.otp = otp;
                existingUser.otpExpires = otpExpires;
                await existingUser.save();

                await sendVerificationEmail(
                    normalizedEmail,
                    "Quizshaala Email Verification",
                    `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
              <p>Hello ${existingUser.name},</p>
              <p>Your OTP is: <strong>${otp}</strong></p>
              <p>This OTP will expire in 10 minutes.</p>
            </div>
          `
                );

                return res.status(200).json({
                    message: 'Email already exists but not verified. OTP resent.',
                    userId: existingUser._id
                });
            }

            // Already verified → block signup
            return res.status(400).json({ error: 'User with this email already exists' });
        }

        // Generate OTP
        const otp = generateOtp();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        // Create user with OTP (not verified yet)
        const user = new User({
            email: normalizedEmail,
            password,
            name,
            otp,
            otpExpires,
            isVerified: false
        });

        await user.save();

        // Send OTP email via SMTP.
        try {
            await sendVerificationEmail(
                normalizedEmail,
                "Quizshaala Email Verification",
                `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
            <p>Hello ${name},</p>
            <p>Thank you for registering with Quizshaala. Please use the following OTP to verify your email address:</p>
            <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
              <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #4F46E5;">${otp}</span>
            </div>
            <p>This OTP will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <br>
            <p>Best regards,<br>Quizshaala Team</p>
          </div>
        `
            );

            res.status(201).json({
                message: 'OTP sent to email. Please verify to complete registration.',
                userId: user._id
            });
        } catch (emailError) {
            console.error('Email sending error:', emailError);
            // Delete the user if email fails
            await User.findByIdAndDelete(user._id);
            return res.status(500).json({
                error: getClientSafeEmailError(emailError, 'Failed to send verification email')
            });
        }
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if OTP matches and is not expired
        if (user.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        if (user.otpExpires < new Date()) {
            return res.status(400).json({ error: 'OTP has expired' });
        }

        //  Reset lock and login attempts
        user.isVerified = true;
        user.otp = null;
        user.otpExpires = null;
        user.loginAttempts = 0;
        user.lockUntil = null;
        await user.save();

        // Generate tokens
        const { accessToken, refreshToken } = user.generateTokens();
        user.refreshToken = refreshToken;
        await user.save();

        res.json({
            message: 'Email verified successfully. Registration complete!',
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                isVerified: user.isVerified
            },
            accessToken,
            refreshToken
        });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const resendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.isVerified) {
            return res.status(400).json({ error: 'Email is already verified' });
        }

        //  Reset lock if user is currently locked
        if (user.isLocked) {
            user.loginAttempts = 0;
            user.lockUntil = null;
        }

        // Generate new OTP
        const otp = generateOtp();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        // Update user with new OTP
        user.otp = otp;
        user.otpExpires = otpExpires;
        await user.save();

        // Send new OTP email via SMTP.
        try {
            await sendVerificationEmail(
                normalizedEmail,
                "Quizshaala New Verification OTP",
                `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
            <p>Hello ${user.name},</p>
            <p>Here is your new verification OTP:</p>
            <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
              <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #4F46E5;">${otp}</span>
            </div>
            <p>This OTP will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <br>
            <p>Best regards,<br>Quizshaala Team</p>
          </div>
        `
            );

            res.json({ message: 'New OTP sent to your email' });
        } catch (emailError) {
            console.error('Email sending error:', emailError);
            return res.status(500).json({
                error: getClientSafeEmailError(emailError, 'Failed to send OTP email')
            });
        }
    } catch (error) {
        console.error('OTP resend route error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = req.body || {};
        const normalizedEmail = email?.trim().toLowerCase();

        if (!normalizedEmail || !password) {
            return res.status(400).json({ error: 'email and password are required' });
        }

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Check if user is verified
        if (!user.isVerified) {
            return res.status(401).json({ error: 'Please verify your email before logging in' });
        }

        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const { accessToken, refreshToken } = user.generateTokens();
        user.refreshToken = refreshToken;
        await user.save();

        res.json({
            message: 'Login successful',
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                isVerified: user.isVerified
            },
            accessToken,
            refreshToken
        });
    } catch (error) {
        console.error('Login error:', error);
        if (error.message.includes('Account is temporarily locked')) {
            return res.status(423).json({ error: error.message });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(401).json({ error: 'Refresh token required' });
        }
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }
        const { accessToken, refreshToken: newRefreshToken } = user.generateTokens();
        user.refreshToken = newRefreshToken;
        await user.save();
        res.json({
            accessToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(403).json({ error: 'Invalid refresh token' });
    }
};

export const logout = async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.userId, { refreshToken: null });
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password -refreshToken');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                isVerified: user.isVerified,
            }
        });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const contactParams = async (req, res) => {
    const { name, email, message } = req.body;

    try {
        await sendEmail(
            process.env.CONTACT_TO_EMAIL || process.env.EMAIL_FROM,
            `New Contact Form Submission from ${name}`,
            message,
            `<p><strong>Name:</strong> ${name}</p>
             <p><strong>Email:</strong> ${email}</p>
             <p><strong>Message:</strong> ${message}</p>`
        );
        res.status(200).json({ message: 'Email sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Email failed', error });
    }
};
