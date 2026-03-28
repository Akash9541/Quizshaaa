# QuizShaala Backend

QuizShaala backend is an Express + MongoDB + Redis service that powers authentication, dynamic quiz generation, quiz history, leaderboards, OTP flows, and live quiz rooms.

## Features

- JWT-based authentication
- OTP email flow for verification and password reset
- Dynamic question generation with Gemini
- Hybrid question pipeline:
  - MongoDB/cache first
  - AI fallback
- Redis caching for frequently used quiz data
- BullMQ-backed background processing
- Real-time quiz rooms with Socket.IO
- Redis-backed live room state for multi-instance support
- Live and topic leaderboards

## Tech Stack

- Node.js
- Express
- MongoDB + Mongoose
- Redis + BullMQ
- Socket.IO
- Google Gemini API
- Brevo transactional email
- Winston logging

## Scripts

```bash
npm install
npm run dev
npm start
```

## Required Environment Variables

Create `backend/.env` for local development.

```env
PORT=5002
NODE_ENV=development

MONGO_URI=mongodb://localhost:27017/quizshaala
REDIS_URL=redis://localhost:6379

FRONTEND_URL=http://localhost:5173
BACKEND_URL=http://localhost:5002

SESSION_SECRET=change-this-session-secret
JWT_SECRET=change-this-jwt-secret
JWT_REFRESH_SECRET=change-this-refresh-secret

BREVO_API_KEY=
EMAIL_FROM=
EMAIL_USER=
EMAIL_PASS=

GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash

USE_MONGO_SESSION_STORE=true
REQUIRE_DB_ON_START=true

LIVE_ROOM_QUESTION_LIMIT=5
LIVE_ROOM_QUESTION_DURATION_MS=30000
LIVE_ROOM_TTL_SECONDS=3600
LIVE_ROOM_COMPLETED_TTL_SECONDS=900
LIVE_ROOM_EMPTY_TTL_SECONDS=120
LIVE_ROOM_TICK_INTERVAL_MS=1000
LIVE_ROOM_TICK_LOCK_MS=800
LIVE_ROOM_ADVANCE_LOCK_MS=3000
```

Optional Gemini retry tuning:

```env
GEMINI_MAX_429_RETRIES=2
GEMINI_DEFAULT_RETRY_DELAY_MS=60000
GEMINI_RETRY_JITTER_MS=1500
GEMINI_MIN_TIME_MS=2000
```

## Local Run

```bash
cd backend
npm install
npm run dev
```

The backend expects MongoDB and Redis to be available before startup when `REQUIRE_DB_ON_START=true`.

## Health Check

```bash
GET /api/health
```

This reports the current MongoDB and Redis connection state.

## Main API Areas

- `/api/signup`, `/api/login`, `/api/logout`
- `/api/send-otp`, `/api/verify-otp`, `/api/reset-password`
- `/api/questions`
- `/api/history`
- `/api/leaderboard/:topic`
- `/api/live/health`

## Real-Time System

Live quiz rooms use Socket.IO with Redis-backed coordination for:

- room creation and join
- synchronized question timers
- answer submission
- room leaderboard broadcasts
- distributed room state across server instances

MongoDB is used for final persistence, while Redis is the source of truth for active live sessions.

## Docker

This repo includes a backend `Dockerfile` and is compatible with the project-level `docker-compose.yml`.

To build only the backend image:

```bash
cd backend
docker build -t quizshaala-backend .
```

## Deployment Notes

- Set all secrets through your deployment provider
- Do not commit real `.env` files
- Use a Redis instance with `maxmemory-policy noeviction`
- Verify Brevo sender identity and allowed IP settings before using OTP email in production
