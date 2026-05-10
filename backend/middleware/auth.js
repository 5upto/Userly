const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
const { checkUserStatusInEntra, checkUserGroupMembership, getTenantGraphToken, findUserAndGetToken } = require('../services/graphApi');
const { isTokenBlacklisted, blacklistToken } = require('../services/tokenBlacklist');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required', redirect: true });
  }

  // Check if token was invalidated by IdP-initiated SLO or block
  const blacklistCheck = isTokenBlacklisted(token);
  if (blacklistCheck.blacklisted) {
    console.log('Rejected blacklisted token, reason:', blacklistCheck.reason);
    const reason = blacklistCheck.reason || 'blocked';
    return res.status(401).json({
      message: blacklistCheck.reason || 'Session invalidated',
      redirect: true,
      reason: reason.toLowerCase().includes('security') ? 'security_group' : 'blocked'
    });
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
      // Get the specific reason from the most recent invalidated session
      const { rows: sessionRows } = await pool.query(
        `SELECT invalidated_reason FROM user_sessions
         WHERE user_id = $1 AND auth_type = 'saml' AND invalidated_reason IS NOT NULL
         ORDER BY invalidated_at DESC NULLS LAST
         LIMIT 1`,
        [user.id]
      );

      const reason = sessionRows[0]?.invalidated_reason || 'Account blocked';
      const isSecurityGroup = reason.toLowerCase().includes('security group') ||
                              reason.toLowerCase().includes('removed from');

      return res.status(403).json({
        message: reason,
        redirect: true,
        reason: isSecurityGroup ? 'security_group' : 'blocked'
      });
    }

    // For SAML users, optionally check real-time status in Entra (if Graph API configured)
    // This enables instant detection of blocks but adds ~200-500ms to API calls
    if (decoded.authType === 'saml') {
      try {
        let graphToken = null;
        let effectiveConfig = null;

        // First, try the tenant from the JWT token (if available)
        if (decoded.tenantGraphCreds) {
          const creds = decoded.tenantGraphCreds;
          if (creds.graphApiEnabled && creds.tenantId && creds.clientId && creds.clientSecret) {
            graphToken = await getTenantGraphToken(creds.tenantId, creds.clientId, creds.clientSecret);
            effectiveConfig = creds;
          }
        }

        // If no token from JWT or user not found in that tenant, search across all configured tenants
        if (!graphToken) {
          console.log(`Searching for user ${user.email} across all configured tenants...`);
          const tenantInfo = await findUserAndGetToken(user.email);
          if (tenantInfo) {
            graphToken = tenantInfo.token;
            effectiveConfig = tenantInfo.config;
          }
        }

        if (!graphToken) {
          console.log(`No Graph API token available for ${user.email}, skipping real-time check`);
        } else {
          // Check 1: Is user blocked in Entra?
          const entraStatus = await checkUserStatusInEntra(user.email, graphToken);

          if (entraStatus && entraStatus.blocked) {
            console.log(`Real-time block detected for ${user.email} in Entra`);

            // Blacklist current token with reason
            blacklistToken(token, 'User blocked in Entra ID');

            // Update local user status
            await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['blocked', user.id]);

            return res.status(403).json({
              message: 'Account blocked in Entra ID',
              redirect: true,
              reason: 'blocked'
            });
          }

          // Check 2: Real-time check - is user still in their tenant's security group?
          const securityGroupId = effectiveConfig?.security_group_id;
          if (securityGroupId) {
            const membership = await checkUserGroupMembership(user.email, securityGroupId, graphToken);
            if (membership && !membership.isMember) {
              console.log(`Real-time: User ${user.email} not in security group ${securityGroupId}`);

              // Blacklist current token with reason
              blacklistToken(token, 'User removed from security group');

              // Update local user status
              await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['blocked', user.id]);

              return res.status(403).json({
                message: 'Access revoked: User removed from security group',
                redirect: true,
                forceReauth: true,
                reason: 'security_group'
              });
            }
          }
        }
      } catch (graphError) {
        // Don't fail the request if Graph API check fails
        console.error('Graph API real-time check failed:', graphError.message);
      }
    }

    req.user = user;
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

module.exports = { authenticateToken, requireRole, requireAdmin, requireSuperAdmin, blacklistToken, isTokenBlacklisted };