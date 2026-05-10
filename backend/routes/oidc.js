const express = require('express');
const router = express.Router();
const passport = require('passport');
const { Strategy: OpenIDConnectStrategy } = require('passport-openidconnect');
const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
const { authenticateToken, requireAdmin, blacklistToken } = require('../middleware/auth');
const {
  discoverOidcConfig,
  validateOidcConfig,
  getOidcConfigById,
  getOidcConfigByDomain,
  loadOidcConfigsFromDb,
  refreshOidcConfigs,
  getAllOidcConfigs,
  updateOidcConfigInMemory,
  removeOidcConfigFromMemory,
  getUserInfo,
  exchangeCodeForToken,
  registerOidcSession,
  invalidateOidcSessions
} = require('../services/oidcService');
const { checkUserStatusInEntra, findUserAndGetToken, checkUserAppAccess } = require('../services/graphApi');

// Load OIDC configs from database on startup
loadOidcConfigsFromDb();

// Store strategies by config ID
const oidcStrategies = {};

// Get OIDC strategy for a specific config
function getOidcStrategy(config, discovery) {
  const strategyName = `oidc-${config.id}`;
  
  if (oidcStrategies[strategyName]) {
    return oidcStrategies[strategyName];
  }

  const strategy = new OpenIDConnectStrategy({
    issuer: config.issuer_url,
    authorizationURL: discovery.authorization_endpoint,
    tokenURL: discovery.token_endpoint,
    userInfoURL: discovery.userinfo_endpoint,
    clientID: config.client_id,
    clientSecret: config.client_secret,
    callbackURL: config.callback_url,
    scope: config.scope || 'openid profile email'
  }, async (iss, sub, profile, accessToken, refreshToken, done) => {
    try {
      // Find or create user based on email
      const email = profile.emails?.[0]?.value || profile.email;
      if (!email) {
        return done(new Error('No email in OIDC profile'));
      }

      // Check if user exists
      const { rows: existingUsers } = await pool.query(
        'SELECT id, name, email, status, role FROM users WHERE email = $1',
        [email]
      );

      let user;
      if (existingUsers.length > 0) {
        user = existingUsers[0];
        
        // Update last login time
        await pool.query(
          'UPDATE users SET last_login_time = NOW() WHERE id = $1',
          [user.id]
        );
      } else {
        // Create new user
        const name = profile.displayName || profile.name?.givenName || email.split('@')[0];
        const { rows: newUsers } = await pool.query(
          'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, status, role',
          [name, email, 'oidc_user']
        );
        user = newUsers[0];
      }

      // Check if user is blocked
      if (user.status === 'blocked') {
        return done(new Error('Account is blocked'));
      }

      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  oidcStrategies[strategyName] = strategy;
  return strategy;
}

// Register all enabled OIDC strategies with passport
async function registerOidcStrategies() {
  const configs = getAllOidcConfigs().filter(c => c.enabled !== false);
  
  for (const config of configs) {
    try {
      const validation = await validateOidcConfig(config);
      if (validation.valid) {
        const strategy = getOidcStrategy(config, validation.discovery);
        const strategyName = `oidc-${config.id}`;
        passport.use(strategyName, strategy);
        console.log(`Registered OIDC strategy: ${strategyName}`);
      }
    } catch (error) {
      console.error(`Failed to register OIDC strategy for config ${config.id}:`, error.message);
    }
  }
}

// Register strategies on startup
registerOidcStrategies();

// Get OIDC providers for login page (public, no auth required)
// Only returns ENABLED configurations without sensitive data
router.get('/providers', (req, res) => {
  // Return only enabled configurations for login page
  const providers = getAllOidcConfigs()
    .filter(c => c.enabled !== false)
    .map(c => ({
      id: c.id,
      oidc_name: c.oidc_name,
      allowed_domains: c.allowed_domains,
      issuer_url: c.issuer_url,
      callback_url: c.callback_url,
      scope: c.scope
    }));
  res.json(providers);
});

// CRUD Operations for OIDC Configurations

// Get all OIDC configurations (admin only)
router.get('/configs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, oidc_name, allowed_domains, issuer_url, client_id, callback_url, scope, response_type, enabled, created_at, updated_at FROM oidc_configs ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching OIDC configs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single OIDC configuration (admin only)
router.get('/configs/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM oidc_configs WHERE id = $1',
      [req.params.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ message: 'OIDC configuration not found' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching OIDC config:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new OIDC configuration (admin only)
router.post('/configs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      oidc_name,
      allowed_domains,
      issuer_url,
      client_id,
      client_secret,
      callback_url,
      scope,
      response_type,
      enabled
    } = req.body;

    if (!oidc_name || !issuer_url || !client_id || !client_secret || !callback_url) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Validate OIDC configuration
    const testConfig = { issuer_url, client_id, client_secret, callback_url, scope, response_type };
    const validation = await validateOidcConfig(testConfig);
    
    if (!validation.valid) {
      return res.status(400).json({ message: 'Invalid OIDC configuration', error: validation.error });
    }

    const { rows } = await pool.query(
      `INSERT INTO oidc_configs (oidc_name, allowed_domains, issuer_url, client_id, client_secret, callback_url, scope, response_type, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        oidc_name,
        allowed_domains || null,
        issuer_url,
        client_id,
        client_secret,
        callback_url,
        scope || 'openid profile email',
        response_type || 'code',
        enabled !== false
      ]
    );

    // Update in-memory cache
    await refreshOidcConfigs();
    
    // Register the new strategy
    const newConfig = rows[0];
    const strategy = getOidcStrategy(newConfig, validation.discovery);
    const strategyName = `oidc-${newConfig.id}`;
    passport.use(strategyName, strategy);

    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Error creating OIDC config:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update OIDC configuration (admin only)
router.put('/configs/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      oidc_name,
      allowed_domains,
      issuer_url,
      client_id,
      client_secret,
      callback_url,
      scope,
      response_type,
      enabled
    } = req.body;

    // Validate OIDC configuration if issuer_url changed
    if (issuer_url) {
      const testConfig = { 
        issuer_url, 
        client_id: client_id || req.body.client_id, 
        client_secret: client_secret || req.body.client_secret,
        callback_url: callback_url || req.body.callback_url,
        scope,
        response_type 
      };
      const validation = await validateOidcConfig(testConfig);
      
      if (!validation.valid) {
        return res.status(400).json({ message: 'Invalid OIDC configuration', error: validation.error });
      }
    }

    const { rows } = await pool.query(
      `UPDATE oidc_configs 
       SET oidc_name = COALESCE($1, oidc_name),
           allowed_domains = COALESCE($2, allowed_domains),
           issuer_url = COALESCE($3, issuer_url),
           client_id = COALESCE($4, client_id),
           client_secret = COALESCE($5, client_secret),
           callback_url = COALESCE($6, callback_url),
           scope = COALESCE($7, scope),
           response_type = COALESCE($8, response_type),
           enabled = COALESCE($9, enabled),
           updated_at = NOW()
       WHERE id = $10
       RETURNING *`,
      [
        oidc_name,
        allowed_domains,
        issuer_url,
        client_id,
        client_secret,
        callback_url,
        scope,
        response_type,
        enabled,
        req.params.id
      ]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'OIDC configuration not found' });
    }

    // Update in-memory cache and re-register strategies
    await refreshOidcConfigs();
    await registerOidcStrategies();

    res.json(rows[0]);
  } catch (error) {
    console.error('Error updating OIDC config:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete OIDC configuration (admin only)
router.delete('/configs/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'DELETE FROM oidc_configs WHERE id = $1 RETURNING *',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'OIDC configuration not found' });
    }

    // Remove from in-memory cache
    removeOidcConfigFromMemory(req.params.id);
    
    // Remove strategy from passport
    const strategyName = `oidc-${req.params.id}`;
    delete oidcStrategies[strategyName];

    res.json({ message: 'OIDC configuration deleted successfully' });
  } catch (error) {
    console.error('Error deleting OIDC config:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Validate OIDC configuration before saving
router.post('/validate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { issuer_url, client_id, client_secret, callback_url } = req.body;

    if (!issuer_url || !client_id || !client_secret || !callback_url) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const validation = await validateOidcConfig(req.body);
    
    if (validation.valid) {
      res.json({ valid: true, discovery: validation.discovery });
    } else {
      res.status(400).json({ valid: false, error: validation.error });
    }
  } catch (error) {
    console.error('Error validating OIDC config:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// OIDC Authentication Routes

// Initiate OIDC login
router.get('/login/:configId', async (req, res) => {
  try {
    const config = getOidcConfigById(req.params.configId);
    
    if (!config) {
      return res.status(404).json({ message: 'OIDC configuration not found' });
    }

    if (!config.enabled) {
      return res.status(403).json({ message: 'OIDC configuration is disabled' });
    }

    const validation = await validateOidcConfig(config);
    
    if (!validation.valid) {
      return res.status(400).json({ message: 'Invalid OIDC configuration', error: validation.error });
    }

    // Generate authorization URL
    // Use a fixed backend callback URL and pass configId in state
    const backendUrl = process.env.BACKEND_URL || 'https://userly-341i.onrender.com';
    const callbackUrl = `${backendUrl}/api/oidc/callback`;
    
    const authUrl = new URL(validation.discovery.authorization_endpoint);
    authUrl.searchParams.append('response_type', config.response_type || 'code');
    authUrl.searchParams.append('client_id', config.client_id);
    authUrl.searchParams.append('redirect_uri', callbackUrl);
    authUrl.searchParams.append('scope', config.scope || 'openid profile email');
    authUrl.searchParams.append('state', req.params.configId); // Pass config ID in state

    res.json({ authorizationUrl: authUrl.toString() });
  } catch (error) {
    console.error('Error initiating OIDC login:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// OIDC callback handler
router.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const configId = state; // Read configId from state parameter

    console.log('OIDC callback received:', { hasCode: !!code, state });

    if (!code) {
      return res.status(400).json({ message: 'Authorization code is required' });
    }

    if (!configId) {
      return res.status(400).json({ message: 'State (configId) is required' });
    }

    const config = getOidcConfigById(configId);
    
    if (!config) {
      console.error('OIDC config not found for configId:', configId);
      return res.status(404).json({ message: 'OIDC configuration not found' });
    }

    console.log('OIDC config found:', config.oidc_name);

    const validation = await validateOidcConfig(config);
    
    if (!validation.valid) {
      console.error('OIDC validation failed:', validation.error);
      return res.status(400).json({ message: 'Invalid OIDC configuration', error: validation.error });
    }

    // Exchange code for tokens
    const backendUrl = process.env.BACKEND_URL || 'https://userly-341i.onrender.com';
    const callbackUrl = `${backendUrl}/api/oidc/callback`;
    console.log('Exchanging code for tokens...');
    const tokens = await exchangeCodeForToken(code, config, validation.discovery, callbackUrl);
    console.log('Tokens received:', { hasAccessToken: !!tokens.access_token, hasIdToken: !!tokens.id_token });
    
    // Decode ID token to get UPN (often included in ID token even if not in userinfo)
    let idTokenClaims = {};
    if (tokens.id_token) {
      try {
        const parts = tokens.id_token.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        idTokenClaims = payload;
        console.log('ID token claims:', idTokenClaims);
      } catch (e) {
        console.error('Failed to decode ID token:', e);
      }
    }
    
    // Get user info
    console.log('Fetching user info from:', validation.discovery.userinfo_endpoint);
    const userInfo = await getUserInfo(tokens.access_token, validation.discovery.userinfo_endpoint);
    console.log('User info received:', userInfo);
    console.log('User info keys:', Object.keys(userInfo));
    
    // Try to get email from various fields - check ID token first, then userinfo
    const email = idTokenClaims.upn || 
                 idTokenClaims.email ||
                 idTokenClaims.preferred_username ||
                 userInfo.email || 
                 userInfo.emails?.[0]?.value || 
                 userInfo.upn ||
                 userInfo.preferred_username ||
                 userInfo.user_principal_name ||
                 userInfo.unique_name ||
                 userInfo.name;
    if (!email) {
      console.error('No email, UPN, or other identifier in user info:', userInfo);
      return res.status(400).json({ message: 'No email or UPN in user info' });
    }
    console.log('Using identifier as email:', email);

    // Check user status in Entra BEFORE allowing login (pre-login check)
    try {
      const entraStatus = await checkUserStatusInEntra(email);
      if (entraStatus && entraStatus.blocked) {
        console.log(`User ${email} is BLOCKED in Entra, denying login`);
        return res.redirect(`${process.env.FRONTEND_URL || 'https://userly-pro.vercel.app'}/login?blocked=true&reason=entra_blocked`);
      }

      // Check security group membership BEFORE allowing login (pre-login check)
      const tenantInfo = await findUserAndGetToken(email);
      if (tenantInfo && tenantInfo.config?.security_group_id) {
        const appAccess = await checkUserAppAccess(email, tenantInfo.config.security_group_id, tenantInfo.token);
        if (appAccess && !appAccess.hasAccess) {
          console.log(`User ${email} does not have security group access, denying login`);
          return res.redirect(`${process.env.FRONTEND_URL || 'https://userly-pro.vercel.app'}/login?blocked=true&reason=no_group_access`);
        }
      }
    } catch (error) {
      // If Graph API call fails due to user being disabled/blocked, treat as blocked
      if (error.message && error.message.includes('disabled')) {
        console.log(`User ${email} appears to be disabled in Entra (Graph API error), denying login`);
        return res.redirect(`${process.env.FRONTEND_URL || 'https://userly-pro.vercel.app'}/login?blocked=true&reason=entra_blocked`);
      }
      // For other errors, log but allow login (fail open)
      console.error('Error during pre-login Entra status check:', error.message);
    }

    // Check if user exists
    const { rows: existingUsers } = await pool.query(
      'SELECT id, name, email, status, role FROM users WHERE email = $1',
      [email]
    );

    let user;
    if (existingUsers.length > 0) {
      user = existingUsers[0];

      if (user.status === 'blocked') {
        return res.status(403).json({ message: 'Account is blocked' });
      }

      // Update last login time
      await pool.query(
        'UPDATE users SET last_login_time = NOW() WHERE id = $1',
        [user.id]
      );
    } else {
      // Create new user
      const name = userInfo.name || userInfo.given_name || email.split('@')[0];
      const { rows: newUsers } = await pool.query(
        'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, status, role',
        [name, email, 'oidc_user']
      );
      user = newUsers[0];
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        name: user.name, 
        role: user.role || 'user',
        authType: 'oidc'
      },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '24h' }
    );

    // Register session
    registerOidcSession(user.id, token);

    // Store session in database
    await pool.query(
      `INSERT INTO user_sessions (user_id, token, auth_type) 
       VALUES ($1, $2, 'oidc')`,
      [user.id, token]
    );

    // Redirect to frontend with token
    const frontendUrl = process.env.FRONTEND_URL || 'https://userly-pro.vercel.app';
    console.log('Redirecting to frontend with token');
    res.redirect(`${frontendUrl}/oidc-callback?token=${token}`);
  } catch (error) {
    console.error('Error in OIDC callback:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ message: 'Authentication failed', error: error.message });
  }
});

// Logout OIDC user
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Blacklist the current token
    blacklistToken(req.token, 'User logout');
    
    // Invalidate all OIDC sessions for this user
    invalidateOidcSessions(userId);
    
    // Mark sessions as inactive in database
    await pool.query(
      `UPDATE user_sessions 
       SET is_active = false, invalidated_at = NOW(), invalidated_reason = 'User logout'
       WHERE user_id = $1 AND auth_type = 'oidc'`,
      [userId]
    );

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error during OIDC logout:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
