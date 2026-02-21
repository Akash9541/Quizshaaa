import crypto from 'node:crypto';
import SibApiV3Sdk from 'sib-api-v3-sdk';
import dotenv from 'dotenv';

dotenv.config();

const OTP_EXPIRATION_MINUTES = Number(process.env.OTP_EXPIRATION_MINUTES || 10);

const parseSender = (emailFrom) => {
    const fallback = { name: 'Quizshaala', email: emailFrom };
    const match = emailFrom.match(/^(.*?)\s*<([^>]+)>$/);
    if (!match) return fallback;
    const name = match[1]?.trim().replace(/^"|"$/g, '') || 'Quizshaala';
    const email = match[2]?.trim();
    return { name, email };
};

const assertEmailConfig = () => {
    if (!process.env.BREVO_API_KEY || !process.env.EMAIL_FROM) {
        throw new Error('Email service is not configured. Set BREVO_API_KEY and EMAIL_FROM.');
    }
};

const getTransactionalApi = () => {
    const apiClient = SibApiV3Sdk.ApiClient.instance;
    apiClient.authentications['api-key'].apiKey = process.env.BREVO_API_KEY;
    return new SibApiV3Sdk.TransactionalEmailsApi();
};

const buildOtpHtml = (otp) => `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
    <p>Your OTP is:</p>
    <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
      <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #4F46E5;">${otp}</span>
    </div>
    <p>This OTP expires in ${OTP_EXPIRATION_MINUTES} minutes.</p>
    <p>If you did not request this, please ignore this email.</p>
  </div>
`;

export const generateOtp = () => crypto.randomInt(0, 1000000).toString().padStart(6, '0');

export const verifyBrevoConfig = async () => {
    assertEmailConfig();
};

export const sendEmail = async (to, subject, text, html) => {
    assertEmailConfig();

    try {
        const emailApi = getTransactionalApi();
        const payload = new SibApiV3Sdk.SendSmtpEmail();

        payload.sender = parseSender(process.env.EMAIL_FROM);
        payload.to = [{ email: to }];
        payload.subject = subject;
        payload.textContent = text;
        payload.htmlContent = html;

        const response = await emailApi.sendTransacEmail(payload);
        return { messageId: response?.messageId || null };
    } catch (error) {
        const details = {
            message: error?.message,
            statusCode: error?.response?.statusCode || error?.statusCode,
            responseBody: error?.response?.body || error?.body,
            stack: error?.stack,
        };
        console.error('Brevo sendEmail error:', details);
        throw new Error('Failed to send email via Brevo API');
    }
};

export const sendOTPEmail = async (toEmail, otp) => {
    const subject = 'Your Quizshaala verification OTP';
    const text = `Your OTP is ${otp}. It expires in ${OTP_EXPIRATION_MINUTES} minutes.`;
    const html = buildOtpHtml(otp);
    return sendEmail(toEmail, subject, text, html);
};
