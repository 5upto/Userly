const jwt = require('jsonwebtoken');

// Token blacklist for IdP-initiated SLO (in production, use Redis/DB)
const tokenBlacklist = new Set();

// Check if token is blacklisted
const isTokenBlacklisted = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.userId || !decoded.iat) return false;
    const key = `${decoded.userId}:${decoded.iat}`;
    return tokenBlacklist.has(key);
  } catch {
    return false;
  }
};

// Add token to blacklist
const blacklistToken = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.userId || !decoded.iat) return;
    const key = `${decoded.userId}:${decoded.iat}`;
    tokenBlacklist.add(key);
    console.log('Token blacklisted for user:', decoded.email);

    // Clean up after 24 hours
    setTimeout(() => tokenBlacklist.delete(key), 24 * 60 * 60 * 1000);
  } catch (e) {
    console.error('Failed to blacklist token:', e);
  }
};

module.exports = { isTokenBlacklisted, blacklistToken };
