import { generateOtp, sendOTPEmail } from '../services/emailService.js';

const isValidEmail = (email = '') => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

export const sendEmailOtp = async (req, res) => {
    try {
        const email = req.body?.email?.trim().toLowerCase();

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Please provide a valid email address' });
        }

        const otp = generateOtp();
        const { messageId } = await sendOTPEmail(email, otp);

        const response = {
            message: 'OTP email sent successfully',
            messageId,
        };

        // Never return OTP in production.
        if (process.env.NODE_ENV !== 'production') {
            response.otp = otp;
        }

        return res.status(200).json(response);
    } catch (error) {
        console.error('sendEmailOtp error:', error);
        const status = error.message.includes('not configured') ? 500 : 502;
        return res.status(status).json({
            error: 'Failed to send OTP email',
            details: process.env.NODE_ENV === 'production' ? undefined : error.message,
        });
    }
};
