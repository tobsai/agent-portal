'use strict';

const { defineConfig } = require('vitest/config');

module.exports = defineConfig({
  test: {
    environment: 'node',
    globals: true,       // makes describe/it/expect available globally — no import needed
    testTimeout: 10000,
    include: ['tests/**/*.test.js'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['lib/**/*.js', 'routes/**/*.js'],
      exclude: ['lib/posthog.js', 'lib/apns.js', 'lib/gateway-client.js'],
    },
  },
});
