const GEMINI_MIN_TIME_MS = Math.max(Number(process.env.GEMINI_MIN_TIME_MS || 2000), 0);

let queuedWork = Promise.resolve();
let lastExecutionStartedAt = 0;
let cooldownUntil = 0;

const sleep = (ms) => new Promise((resolve) => {
    setTimeout(resolve, ms);
});

const waitForWindow = async () => {
    const now = Date.now();
    const earliestStart = Math.max(
        now,
        cooldownUntil,
        lastExecutionStartedAt + GEMINI_MIN_TIME_MS
    );

    if (earliestStart > now) {
        await sleep(earliestStart - now);
    }

    lastExecutionStartedAt = Date.now();
};

export const scheduleGeminiRequest = (task) => {
    const runTask = async () => {
        await waitForWindow();
        return task();
    };

    const scheduled = queuedWork.then(runTask, runTask);
    queuedWork = scheduled.catch(() => undefined);
    return scheduled;
};

export const registerGeminiCooldown = (delayMs) => {
    if (!delayMs || delayMs <= 0) {
        return;
    }

    cooldownUntil = Math.max(cooldownUntil, Date.now() + delayMs);
};
