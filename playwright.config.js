// @ts-check
const { defineConfig } = require("@playwright/test");

const PORT = 4210;

module.exports = defineConfig({
    testDir: "./test/e2e",
    fullyParallel: false,
    retries: process.env.CI ? 1 : 0,
    use: {
        baseURL: `http://localhost:${PORT}`,
        // Lets sandboxed/CI environments with a pre-installed browser at a
        // custom path point to it instead of triggering a download.
        ...(process.env.PLAYWRIGHT_CHROMIUM_PATH
            ? { launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH } }
            : {})
    },
    webServer: {
        command: "node app.js",
        url: `http://localhost:${PORT}`,
        reuseExistingServer: !process.env.CI,
        env: {
            PORT: String(PORT),
            DB_PATH: "test-e2e.db",
            UPLOADS_DIR: "test-e2e-uploads"
        }
    }
});
