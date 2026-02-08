/**
 * PostHog Analytics Utilities
 * 
 * Usage:
 *   const { posthog, captureEvent, isFeatureEnabled } = require('./lib/posthog');
 *   
 *   // Track an event
 *   captureEvent('work_item_created', { agentId: 'abc', title: 'Task' });
 *   
 *   // Check feature flags
 *   const enabled = await isFeatureEnabled('new-dashboard', 'user-123');
 */

const { PostHog } = require('posthog-node');

let posthog = null;

if (process.env.POSTHOG_API_KEY) {
  posthog = new PostHog(process.env.POSTHOG_API_KEY, {
    host: 'https://analytics.mtree.io',
  });
}

/**
 * Capture an analytics event
 * @param {string} event - Event name
 * @param {object} properties - Event properties
 * @param {string} distinctId - User/agent identifier (optional)
 */
function captureEvent(event, properties = {}, distinctId = 'anonymous') {
  if (posthog) {
    posthog.capture({
      distinctId,
      event,
      properties,
    });
  }
}

/**
 * Check if a feature flag is enabled for a user/agent
 * @param {string} flagKey - Feature flag key
 * @param {string} distinctId - User/agent identifier
 * @returns {Promise<boolean>} Whether the flag is enabled
 */
async function isFeatureEnabled(flagKey, distinctId) {
  if (!posthog) {
    return false;
  }
  
  try {
    const isEnabled = await posthog.isFeatureEnabled(flagKey, distinctId);
    return isEnabled || false;
  } catch (error) {
    console.error('Error checking feature flag:', error);
    return false;
  }
}

/**
 * Identify a user/agent with properties
 * @param {string} distinctId - User/agent identifier
 * @param {object} properties - User properties
 */
function identifyUser(distinctId, properties = {}) {
  if (posthog) {
    posthog.identify({
      distinctId,
      properties,
    });
  }
}

/**
 * Shutdown PostHog client gracefully
 */
async function shutdown() {
  if (posthog) {
    await posthog.shutdown();
  }
}

module.exports = {
  posthog,
  captureEvent,
  isFeatureEnabled,
  identifyUser,
  shutdown,
};
