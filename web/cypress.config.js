export default {
    e2e: {
        baseUrl: process.env.CYPRESS_BASE_URL || "http://127.0.0.1:5173",
        specPattern: "cypress/e2e/**/*.cy.js",
        supportFile: "cypress/support/e2e.js",
        video: false,
        screenshotOnRunFailure: true,
        defaultCommandTimeout: 8000,
        viewportWidth: 1440,
        viewportHeight: 900
    }
};
