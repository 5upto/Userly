const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required', redirect: true });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
    
    const { rows: users } = await pool.query(
      'SELECT id, email, name, status, role FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'User not found', redirect: true });
    }

    const user = users[0];
    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'Account blocked', redirect: true });
    }

    // For SAML users, check if session has been revoked (SLO or blocked)
    if (decoded.authMethod === 'saml') {
      // Check if user has any revoked sessions after their token was issued
      const { rows: revokedSessions } = await pool.query(
        `SELECT id, reason, revoked_at FROM revoked_sessions 
         WHERE user_id = $1 
         AND revoked_at > $2
         ORDER BY revoked_at DESC 
         LIMIT 1`,
        [decoded.userId, new Date(decoded.iat * 1000)]
      );

      if (revokedSessions.length > 0) {
        const session = revokedSessions[0];
        console.log(`SAML session revoked for user ${user.email}: ${session.reason} at ${session.revoked_at}`);
        return res.status(403).json({ 
          message: `Session ${session.reason === 'blocked' ? 'terminated due to account being blocked' : 'logged out from identity provider'}`, 
          redirect: true,
          reason: session.reason
        });
      }

      // Also check if this specific SAML session index was revoked
      if (decoded.samlSessionIndex) {
        const { rows: sessionRevoked } = await pool.query(
          `SELECT id FROM revoked_sessions 
           WHERE saml_session_index = $1 
           AND revoked_at > $2`,
          [decoded.samlSessionIndex, new Date(decoded.iat * 1000)]
        );

        if (sessionRevoked.length > 0) {
          console.log(`Specific SAML session revoked for user ${user.email}, sessionIndex: ${decoded.samlSessionIndex}`);
          return res.status(403).json({ 
            message: 'Session terminated from identity provider', 
            redirect: true,
            reason: 'logout'
          });
        }
      }
    }

    // Attach full token data to req.user for potential use in routes
    req.user = { ...user, ...decoded };
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token', redirect: true });
  }
};

// Middleware to require specific role
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    next();
  };
};

// Middleware to require Admin or Super Admin
const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Middleware to require Super Admin only
const requireSuperAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ message: 'Super Admin access required' });
  }
  next();
};

module.exports = { authenticateToken, requireRole, requireAdmin, requireSuperAdmin };