import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const SMTP_HOST = 'smtp.gmail.com';
const SMTP_PORT = 587;
const OTP_EXPIRATION_MINUTES = Number(process.env.OTP_EXPIRATION_MINUTES || 10);

const assertEmailConfig = () => {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        throw new Error('Email service is not configured. Set EMAIL_USER and EMAIL_PASS.');
    }
};

const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: false,
    requireTLS: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
    pool: true,
    maxConnections: 3,
    maxMessages: 100,
});

const getFromAddress = () => `Quizshaala <${process.env.EMAIL_USER}>`;

export const generateOtp = () => crypto.randomInt(100000, 1000000).toString();

export const verifyEmailTransport = async () => {
    assertEmailConfig();
    await transporter.verify();
};

export const sendEmail = async (to, subject, text, html) => {
    assertEmailConfig();

    const info = await transporter.sendMail({
        from: getFromAddress(),
        to,
        subject,
        text,
        html,
    });

    return {
        messageId: info.messageId,
        accepted: info.accepted,
        rejected: info.rejected,
    };
};

export const sendOtpEmail = async (email, name = 'User') => {
    const otp = generateOtp();
    const subject = 'Your Quizshaala verification OTP';
    const text = `Hello ${name}, your OTP is ${otp}. It expires in ${OTP_EXPIRATION_MINUTES} minutes.`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #4F46E5;">Quizshaala Email Verification</h2>
        <p>Hello ${name},</p>
        <p>Your OTP is:</p>
        <div style="background-color: #f3f4f6; padding: 16px; text-align: center; margin: 20px 0;">
          <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #4F46E5;">${otp}</span>
        </div>
        <p>This OTP expires in ${OTP_EXPIRATION_MINUTES} minutes.</p>
      </div>
    `;

    const result = await sendEmail(email, subject, text, html);
    return { otp, ...result };
};
