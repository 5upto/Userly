const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
const { checkUserStatusInEntra, checkUserGroupMembership, getTenantGraphToken } = require('../services/graphApi');
const { isTokenBlacklisted, blacklistToken } = require('../services/tokenBlacklist');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required', redirect: true });
  }

  // Check if token was invalidated by IdP-initiated SLO
  if (isTokenBlacklisted(token)) {
    console.log('Rejected blacklisted token');
    return res.status(401).json({ message: 'Session invalidated by IdP logout', redirect: true });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
    
    const { rows: users } = await pool.query(
      'SELECT id, email, name, status, role, entra_id FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'User not found', redirect: true });
    }

    const user = users[0];
    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'Account blocked', redirect: true });
    }

    // For SAML users, optionally check real-time status in Entra (if Graph API configured)
    // This enables instant detection of blocks but adds ~200-500ms to API calls
    if (decoded.authType === 'saml' && decoded.tenantGraphCreds) {
      const creds = decoded.tenantGraphCreds;
      if (creds.graphApiEnabled && creds.tenantId && creds.clientId && creds.clientSecret) {
        try {
          // Get tenant-specific token
          const graphToken = await getTenantGraphToken(creds.tenantId, creds.clientId, creds.clientSecret);

          if (!graphToken) {
            console.log(`Failed to get Graph token for ${user.email}'s tenant, skipping real-time check`);
          } else {
            // Use Entra ID if available, otherwise fall back to email
            const userLookupId = creds.userEntraId || user.entra_id || user.email;
            console.log(`Checking Entra status for user using: ${creds.userEntraId ? 'Entra ID' : user.entra_id ? 'stored Entra ID' : 'email'}`);

            // Check 1: Is user blocked in Entra?
            const entraStatus = await checkUserStatusInEntra(userLookupId, graphToken);

            if (entraStatus && entraStatus.blocked) {
              console.log(`Real-time block detected for ${user.email} in Entra`);

              // Blacklist current token
              blacklistToken(token);

              // Update local user status
              await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['blocked', user.id]);

              return res.status(403).json({
                message: 'Account blocked in Entra ID',
                redirect: true,
                reason: 'blocked'
              });
            }

            // Check 2: Real-time check - is user still in their tenant's security group?
            if (creds.securityGroupId) {
              const membership = await checkUserGroupMembership(userLookupId, creds.securityGroupId, graphToken);
              if (membership && !membership.isMember) {
                console.log(`Real-time: User ${user.email} not in security group ${creds.securityGroupId}`);

                // Blacklist current token
                blacklistToken(token);

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