import winston from 'winston';

const isProduction = process.env.NODE_ENV === 'production';
const defaultLevel = process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug');

const baseFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true })
);

const developmentFormat = winston.format.combine(
    baseFormat,
    winston.format.colorize(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        const extra = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
        return `${timestamp} ${level}: ${message}${extra}`;
    })
);

const productionFormat = winston.format.combine(
    baseFormat,
    winston.format.json()
);

export const logger = winston.createLogger({
    level: defaultLevel,
    defaultMeta: {
        service: 'quizshaala-backend'
    },
    format: isProduction ? productionFormat : developmentFormat,
    transports: [
        new winston.transports.Console()
    ]
});

export const requestLogger = (req, res, next) => {
    const startTime = Date.now();

    res.on('finish', () => {
        logger.info('HTTP request completed', {
            method: req.method,
            path: req.originalUrl,
            statusCode: res.statusCode,
            durationMs: Date.now() - startTime,
            ip: req.ip
        });
    });

    next();
};
