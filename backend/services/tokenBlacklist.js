const jwt = require('jsonwebtoken');

// Token blacklist for IdP-initiated SLO (in production, use Redis/DB)
// Map: key -> { reason, timestamp }
const tokenBlacklist = new Map();

// Check if token is blacklisted and get the reason
const isTokenBlacklisted = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.userId || !decoded.iat) return { blacklisted: false };
    const key = `${decoded.userId}:${decoded.iat}`;
    const entry = tokenBlacklist.get(key);
    if (entry) {
      return { blacklisted: true, reason: entry.reason };
    }
    return { blacklisted: false };
  } catch {
    return { blacklisted: false };
  }
};

// Add token to blacklist with optional reason
const blacklistToken = (token, reason = null) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.userId || !decoded.iat) return;
    const key = `${decoded.userId}:${decoded.iat}`;
    tokenBlacklist.set(key, { reason, timestamp: Date.now() });
    console.log('Token blacklisted for user:', decoded.email, 'reason:', reason);

    // Clean up after 24 hours
    setTimeout(() => tokenBlacklist.delete(key), 24 * 60 * 60 * 1000);
  } catch (e) {
    console.error('Failed to blacklist token:', e);
  }
};

module.exports = { isTokenBlacklisted, blacklistToken };
