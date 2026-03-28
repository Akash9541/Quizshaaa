import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { logger } from '../services/logger.js';
dotenv.config();

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // STARTTLS on 587
    requireTLS: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    connectionTimeout: 15000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
});

export const sendEmail = async (to, subject, text, html) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        text,
        html,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        logger.info(`Message sent: ${info.messageId}`);
        return info;
    } catch (error) {
        logger.error('Error sending email', { error: error.message });
        throw error;
    }
};
