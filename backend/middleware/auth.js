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
    
    // Check if SAML session is still active (for SAML-authenticated users)
    if (decoded.jti) {
      const { rows: sessions } = await pool.query(
        `SELECT is_active, logged_out_at FROM saml_sessions 
         WHERE token_jti = $1 
         ORDER BY created_at DESC LIMIT 1`,
        [decoded.jti]
      );
      
      if (sessions.length > 0 && !sessions[0].is_active) {
        console.log('Token invalidated due to SAML Single Logout. JTI:', decoded.jti);
        return res.status(401).json({ 
          message: 'Session terminated - logged out via identity provider', 
          redirect: true,
          samlLogout: true 
        });
      }
    }
    
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

    // Attach jti to user object for potential logout use
    req.user = { ...user, jti: decoded.jti };
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