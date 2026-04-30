const express = require('express');
const router = express.Router();
const multer = require('multer');
const xml2js = require('xml2js');
const fs = require('fs');
const path = require('path');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
const { authenticateToken, requireAdmin, blacklistToken } = require('../middleware/auth');

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const upload = multer({
  dest: uploadsDir,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// In-memory storage for SAML configurations (in production, use a database)
let samlConfigs = [];

// Store strategies by config ID
const strategies = {};

// Session tracking for IdP-initiated SLO: userId -> Set of active tokens
const userSessions = new Map();

// Register a token for a user session (called after successful SAML login)
function registerUserSession(userId, token) {
  if (!userSessions.has(userId)) {
    userSessions.set(userId, new Set());
  }
  userSessions.get(userId).add(token);
  console.log('Registered session for user:', userId);
}

// Invalidate all tokens for a user (called during IdP-initiated SLO)
function invalidateUserSessions(userId) {
  const tokens = userSessions.get(userId);
  if (tokens) {
    tokens.forEach(token => blacklistToken(token));
    userSessions.delete(userId);
    console.log('Invalidated all sessions for user:', userId);
  }
}

// Load SAML configs from database on startup
const loadSamlConfigsFromDb = async () => {
  try {
    console.log('Loading SAML configurations from database...');
    const { rows } = await pool.query(
      'SELECT * FROM saml_configs ORDER BY created_at DESC'
    );

    if (rows && rows.length > 0) {
      console.log(`Found ${rows.length} SAML configuration(s) in database`);

      // Transform database rows to config objects (including new multi-tenant fields)
      samlConfigs = rows.map(row => ({
        id: row.id,
        saml_name: row.saml_name,
        allowed_domains: row.allowed_domains,
        issuer_url: row.issuer_url,
        idp_sso_url: row.idp_sso_url,
        idp_slo_url: row.idp_slo_url,
        idp_certificate: row.idp_certificate,
        enabled: row.enabled !== false, // default true
        tenant_id: row.tenant_id,
        client_id: row.client_id,
        client_secret: row.client_secret,
        graph_api_enabled: row.graph_api_enabled === true,
        saml_app_id: row.saml_app_id,
        security_group_id: row.security_group_id,
        created_at: row.created_at
      }));

      // Register each ENABLED config's strategy with passport
      samlConfigs.filter(c => c.enabled !== false).forEach(config => {
        const strategy = getSamlStrategy(config);
        const strategyName = `saml-${config.id}`;
        passport.use(strategyName, strategy);
        console.log(`Registered SAML strategy: ${strategyName} (enabled: ${config.enabled})`);
      });

      console.log('SAML configurations loaded and strategies registered successfully');
    } else {
      console.log('No SAML configurations found in database');
    }
  } catch (error) {
    console.error('Failed to load SAML configs from database:', error);
  }
};

// Call load function on module initialization
setTimeout(loadSamlConfigsFromDb, 1000); // Delay to ensure DB is connected

// Function to create SAML strategy for a given config (no caching to ensure updates take effect)
const getSamlStrategy = (config) => {
  const strategyName = `saml-${config.id}`;

  const strategy = new SamlStrategy(
    {
      name: strategyName,
      entryPoint: config.idp_sso_url,
      issuer: `userly-${config.id}`,
      cert: config.idp_certificate,
      callbackUrl: 'https://userly-341i.onrender.com/api/saml/acs',
      identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      passReqToCallback: true
    },
    async (req, profile, done) => {
      try {
        // Extract user information from SAML profile
        const email = profile.nameID || profile.email;
        const name = profile.displayName || profile.name || email.split('@')[0];
        
        // Check if user exists
        const { rows: existingUsers } = await pool.query(
          'SELECT id, email, name, status, role FROM users WHERE email = $1',
          [email]
        );

        let user;
        if (existingUsers.length === 0) {
          // Create new user
          const { rows: newUsers } = await pool.query(
            'INSERT INTO users (name, email, password, role, created_at, last_login_time) VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING id, email, name, status, role',
            [name, email, '', 'standard'] // Empty password for SAML users, default role
          );
          user = newUsers[0];
        } else {
          // Update existing user's last login time
          user = existingUsers[0];
          if (user.status === 'blocked') {
            const err = new Error('Account is blocked');
            err.name = 'AccountBlockedError';
            return done(err, null);
          }
          await pool.query(
            'UPDATE users SET last_login_time = NOW() WHERE id = $1',
            [user.id]
          );
        }

        done(null, user);
      } catch (error) {
        console.error('SAML profile processing error:', error);
        done(error, null);
      }
    }
  );

  // Remove old strategy if exists and register new one
  if (passport._strategies[strategyName]) {
    delete passport._strategies[strategyName];
  }
  passport.use(strategy);
  return strategy;
};

// Get all SAML configurations (Admin only)
router.get('/configs', authenticateToken, requireAdmin, (req, res) => {
  res.json(samlConfigs);
});

// Get SAML providers for login page (public, no auth required)
// Only returns ENABLED configurations
router.get('/providers', (req, res) => {
  // Return only enabled configurations for login page
  const providers = samlConfigs
    .filter(c => c.enabled !== false)
    .map(c => ({
      id: c.id,
      saml_name: c.saml_name,
      allowed_domains: c.allowed_domains,
      issuer_url: c.issuer_url,
      idp_slo_url: c.idp_slo_url,
      tenant_id: c.tenant_id,
      saml_app_id: c.saml_app_id,
      security_group_id: c.security_group_id
    }));
  res.json(providers);
});

// Diagnostic endpoint to check SAML status (no auth required for debugging)
router.get('/status', async (req, res) => {
  // Also query DB directly for comparison
  let dbConfigs = [];
  let schemaInfo = [];
  try {
    const { rows } = await pool.query('SELECT id, saml_name, idp_sso_url, idp_slo_url, enabled, tenant_id, client_id, graph_api_enabled FROM saml_configs');
    dbConfigs = rows;
    // Get column info
    const { rows: cols } = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'saml_configs'
    `);
    schemaInfo = cols;
  } catch (e) {
    dbConfigs = [{ error: e.message }];
  }

  res.json({
    configsCount: samlConfigs.length,
    memoryConfigs: samlConfigs.map(c => ({ id: c.id, name: c.saml_name, enabled: c.enabled, sloUrl: c.idp_slo_url })),
    dbConfigs: dbConfigs,
    schemaColumns: schemaInfo,
    strategiesRegistered: Object.keys(passport._strategies || {}).filter(k => k.startsWith('saml-')).length
  });
});

// Test route to verify routing works
router.get('/test', (req, res) => {
  res.json({ message: 'SAML routes are working', timestamp: new Date().toISOString() });
});

// OPTIONS handler for CORS preflight
router.options('/acs', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.sendStatus(200);
});

// Create or update SAML configuration
router.post('/config', authenticateToken, requireAdmin, upload.single('metadataFile'), async (req, res) => {
  try {
    console.log('SAML config save request received');
    console.log('Request body keys:', Object.keys(req.body));
    console.log('Has file:', !!req.file);
    const { samlName, allowedDomains, issuerUrl, idpSsoUrl, idpSloUrl, idpCertificate,
            enabled, tenantId, clientId, clientSecret, graphApiEnabled, samlAppId, securityGroupId } = req.body;
    console.log('Config name:', samlName, 'Enabled:', enabled);

    // Parse metadata file if provided
    let parsedMetadata = null;
    if (req.file) {
      try {
        const xmlData = fs.readFileSync(req.file.path, 'utf8');
        const parser = new xml2js.Parser();
        parsedMetadata = await parser.parseStringPromise(xmlData);
        
        // Extract values from metadata if not provided manually
        if (!issuerUrl && parsedMetadata.EntityDescriptor?.['$']?.entityID) {
          req.body.issuerUrl = parsedMetadata.EntityDescriptor['$'].entityID;
        }
        if (!idpSsoUrl && parsedMetadata.EntityDescriptor?.IDPSSODescriptor?.[0]?.SingleSignOnService?.[0]?.['$']?.Location) {
          req.body.idpSsoUrl = parsedMetadata.EntityDescriptor.IDPSSODescriptor[0].SingleSignOnService[0]['$'].Location;
        }
        if (!idpCertificate && parsedMetadata.EntityDescriptor?.IDPSSODescriptor?.[0]?.KeyDescriptor?.[0]?.KeyInfo?.[0]?.X509Data?.[0]?.X509Certificate?.[0]) {
          req.body.idpCertificate = parsedMetadata.EntityDescriptor.IDPSSODescriptor[0].KeyDescriptor[0].KeyInfo[0].X509Data[0].X509Certificate[0];
        }
        // Extract SingleLogoutService URL from metadata
        if (!idpSloUrl && parsedMetadata.EntityDescriptor?.IDPSSODescriptor?.[0]?.SingleLogoutService?.[0]?.['$']?.Location) {
          req.body.idpSloUrl = parsedMetadata.EntityDescriptor.IDPSSODescriptor[0].SingleLogoutService[0]['$'].Location;
        }

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
      } catch (parseError) {
        console.error('Error parsing metadata file:', parseError);
        // Clean up uploaded file even if parsing fails
        if (req.file && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        // Continue with manual values if metadata parsing fails
      }
    }

    const config = {
      id: Date.now(),
      saml_name: samlName,
      allowed_domains: allowedDomains,
      issuer_url: req.body.issuerUrl || issuerUrl,
      idp_sso_url: req.body.idpSsoUrl || idpSsoUrl,
      idp_slo_url: req.body.idpSloUrl || idpSloUrl,
      idp_certificate: req.body.idpCertificate || idpCertificate,
      enabled: enabled === 'true' || enabled === true,
      tenant_id: tenantId || null,
      client_id: clientId || null,
      client_secret: clientSecret || null,
      graph_api_enabled: graphApiEnabled === 'true' || graphApiEnabled === true,
      saml_app_id: samlAppId || null,
      security_group_id: securityGroupId || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Save to database for persistence
    let savedConfig = null;
    try {
      // First ensure columns exist
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true`);
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255)`);
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS client_id VARCHAR(255)`);
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS client_secret TEXT`);
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS graph_api_enabled BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS saml_app_id VARCHAR(255)`);
      await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS security_group_id VARCHAR(255)`);

      // Insert new config - use serial id from DB, not the Date.now()
      const { rows } = await pool.query(
        `INSERT INTO saml_configs (saml_name, allowed_domains, issuer_url, idp_sso_url, idp_slo_url, idp_certificate,
          enabled, tenant_id, client_id, client_secret, graph_api_enabled, saml_app_id, security_group_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING *`,
        [config.saml_name, config.allowed_domains, config.issuer_url,
         config.idp_sso_url, config.idp_slo_url, config.idp_certificate,
         config.enabled, config.tenant_id, config.client_id, config.client_secret,
         config.graph_api_enabled, config.saml_app_id, config.security_group_id]
      );
      savedConfig = rows[0];
      // Update config with DB id
      config.id = savedConfig.id;
      console.log('SAML config saved to database:', savedConfig.id, 'Enabled:', savedConfig.enabled);
    } catch (dbError) {
      console.error('Failed to save SAML config to database:', dbError.message);
      // Continue with in-memory only if DB fails
    }

    samlConfigs.push(config);

    // Register the SAML strategy with passport (only if enabled)
    if (config.enabled !== false) {
      const strategy = getSamlStrategy(config);
      const strategyName = `saml-${config.id}`;
      passport.use(strategyName, strategy);
      console.log(`Registered new SAML strategy: ${strategyName}`);
    } else {
      console.log(`SAML config saved but disabled: ${config.id}`);
    }

    // Return config with database values
    res.status(201).json(savedConfig || config);
  } catch (error) {
    console.error('Error saving SAML config:', error);
    res.status(500).json({ message: 'Failed to save SAML configuration: ' + error.message });
  }
});

// Toggle SAML configuration enabled status
router.patch('/config/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const requestedId = req.params.id;
    const id = parseInt(requestedId);
    const { enabled } = req.body;

    console.log(`Toggling SAML config ${requestedId} (parsed: ${id}) to enabled: ${enabled}`);

    // Ensure column exists
    await pool.query(`ALTER TABLE saml_configs ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true`);

    // Update in database - try both string and numeric ID
    let rows = [];
    try {
      const result = await pool.query(
        `UPDATE saml_configs SET enabled = $1, updated_at = NOW() WHERE id = $2 RETURNING *`,
        [enabled, id]
      );
      rows = result.rows;
    } catch (dbErr) {
      // If numeric ID fails, try as string (for old Date.now() IDs)
      const result = await pool.query(
        `UPDATE saml_configs SET enabled = $1, updated_at = NOW() WHERE id::text = $2 RETURNING *`,
        [enabled, requestedId]
      );
      rows = result.rows;
    }

    if (rows.length === 0) {
      console.log(`Config ${requestedId} not found in DB, updating in-memory only`);
    }

    // Update in memory - handle both string and numeric IDs
    const configIndex = samlConfigs.findIndex(c =>
      c.id == requestedId || parseInt(c.id) === id
    );
    if (configIndex !== -1) {
      samlConfigs[configIndex].enabled = enabled;

      // Register or unregister strategy based on enabled status
      const config = samlConfigs[configIndex];
      const strategyName = `saml-${config.id}`;

      if (enabled) {
        const strategy = getSamlStrategy(config);
        passport.use(strategyName, strategy);
        console.log(`Strategy ${strategyName} registered (enabled)`);
      } else {
        // Remove strategy from passport
        if (passport._strategies[strategyName]) {
          delete passport._strategies[strategyName];
          console.log(`Strategy ${strategyName} unregistered (disabled)`);
        }
      }
    }

    res.json({
      message: `Configuration ${enabled ? 'enabled' : 'disabled'}`,
      config: rows[0] || samlConfigs[configIndex]
    });
  } catch (error) {
    console.error('Error toggling SAML config:', error.message);
    res.status(500).json({ message: 'Failed to toggle configuration: ' + error.message });
  }
});

// Delete SAML configuration
router.delete('/config/:id', authenticateToken, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);

  // Remove from database
  try {
    await pool.query('DELETE FROM saml_configs WHERE id = $1', [id]);
    console.log('SAML config deleted from database:', id);
  } catch (dbError) {
    console.error('Failed to delete SAML config from database:', dbError);
  }

  // Remove strategy from passport if exists
  const config = samlConfigs.find(c => parseInt(c.id) === id);
  if (config) {
    const strategyName = `saml-${config.id}`;
    if (passport._strategies[strategyName]) {
      delete passport._strategies[strategyName];
    }
  }

  // Remove from memory - handle both string and number IDs
  const initialLength = samlConfigs.length;
  samlConfigs = samlConfigs.filter(config => parseInt(config.id) !== id);
  console.log('Removed from memory:', initialLength - samlConfigs.length, 'configs');
  res.json({ message: 'Configuration deleted successfully' });
});

// Generate SAML metadata for service provider
router.get('/metadata/:id', (req, res) => {
  const requestedId = req.params.id;
  // Handle both old Date.now() string IDs and new SERIAL numeric IDs
  const config = samlConfigs.find(c =>
    c.id == requestedId || parseInt(c.id) == parseInt(requestedId)
  );

  if (!config) {
    console.error('Metadata download: Config not found for id:', requestedId);
    console.error('Available configs:', samlConfigs.map(c => ({ id: c.id, type: typeof c.id, name: c.saml_name })));
    return res.status(404).json({ message: 'Configuration not found' });
  }

  const appId = `userly-${config.id}`;
  const acsUrl = 'https://userly-341i.onrender.com/api/saml/acs';
  const sloUrl = 'https://userly-341i.onrender.com/api/saml/slo';

  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${appId}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${acsUrl}" index="1"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acsUrl}" index="2"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sloUrl}"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Content-Disposition', 'attachment; filename="saml-metadata.xml"');
  res.send(metadata);
});

// SAML login initiation endpoint
router.get('/login/:id', (req, res, next) => {
  try {
    console.log('SAML login initiation request for ID:', req.params.id);
    console.log('Available configs:', samlConfigs.map(c => ({ id: c.id, name: c.saml_name, enabled: c.enabled })));

    const config = samlConfigs.find(c => c.id === parseInt(req.params.id));

    if (!config) {
      console.error('SAML configuration not found for ID:', req.params.id);
      return res.status(404).json({ message: 'SAML configuration not found' });
    }

    // Check if config is enabled
    if (config.enabled === false) {
      console.error('SAML configuration is disabled:', req.params.id);
      return res.status(403).json({ message: 'SAML SSO is disabled for this configuration' });
    }

    const strategyName = `saml-${config.id}`;
    
    console.log('Initiating SAML login for config:', config.id, config.saml_name);
    console.log('Strategy name:', strategyName);
    console.log('IdP SSO URL:', config.idp_sso_url);
    
    // Use standard passport-saml authentication
    passport.authenticate(strategyName, {
      additionalParams: {
        RelayState: 'https://userly-pro.vercel.app/auth/callback'
      }
    })(req, res, next);
  } catch (error) {
    console.error('SAML login initiation error:', error);
    res.status(500).json({ message: 'SAML login initiation failed', error: error.message });
  }
});

// SAML ACS (Assertion Consumer Service) endpoint - handles POST (HTTP-POST binding)
router.post('/acs', (req, res, next) => {
  try {
    console.log('SAML ACS received POST request');
    console.log('Request body keys:', Object.keys(req.body));
    console.log('SAMLResponse present:', !!req.body.SAMLResponse);
    console.log('RelayState:', req.body.RelayState);
    console.log('Available SAML configs:', samlConfigs.length);

    if (samlConfigs.length === 0) {
      console.error('No SAML configuration found');
      return res.redirect('https://userly-pro.vercel.app/login?error=no_saml_config');
    }

    // For multi-tenant, we need to identify which config was used from the SAML response
    // The SAML response contains Issuer which we can match to our configs
    // For now, try each enabled config until one works
    let currentConfigIndex = 0;

    const tryNextConfig = () => {
      // Find next enabled config
      while (currentConfigIndex < samlConfigs.length) {
        const cfg = samlConfigs[currentConfigIndex];
        if (cfg.enabled !== false) {
          break;
        }
        currentConfigIndex++;
      }

      if (currentConfigIndex >= samlConfigs.length) {
        console.error('No enabled SAML configuration found');
        return res.redirect('https://userly-pro.vercel.app/login?error=no_enabled_saml_config');
      }

      const config = samlConfigs[currentConfigIndex];
      const strategyName = `saml-${config.id}`;

      console.log('Trying strategy:', strategyName, 'for config:', config.saml_name);

      passport.authenticate(strategyName, {
        failureRedirect: 'https://userly-pro.vercel.app/login?error=auth_failed',
        failureFlash: true,
        session: false
      }, (err, profile, info) => {
        if (err) {
          // If this config fails, try next one
          if (err.name === 'Error' && err.message?.includes('Invalid')) {
            console.log(`Strategy ${strategyName} failed, trying next...`);
            currentConfigIndex++;
            return tryNextConfig();
          }
          console.error('Passport authentication error:', err);
          if (err.name === 'AccountBlockedError') {
            return res.redirect('https://userly-pro.vercel.app/login?blocked=true&reason=account_locked');
          }
          const errorMsg = encodeURIComponent(err.message || 'Unknown error');
          return res.redirect(`https://userly-pro.vercel.app/login?error=passport_error&details=${errorMsg}`);
        }
        if (!profile) {
          console.error('No profile returned from passport');
          return res.redirect('https://userly-pro.vercel.app/login?error=no_profile');
        }

        console.log('SAML authentication successful with config:', config.id, config.saml_name);
        console.log('Profile:', profile);

        // Pass the config to handleSamlUser so it can use tenant-specific Graph API
        handleSamlUser(profile, res, config);
      })(req, res, next);
    };

    tryNextConfig();
  } catch (error) {
    console.error('SAML ACS error:', error);
    console.error('Error stack:', error.stack);
    const errorMsg = encodeURIComponent(error.message || 'Unknown error');
    res.redirect(`https://userly-pro.vercel.app/login?error=acs_failed&details=${errorMsg}`);
  }
});

async function handleSamlUser(profile, res, samlConfig) {
  try {
    const email = profile.nameID || profile.email;
    const name = profile.displayName || profile.name || email.split('@')[0];

    console.log('Extracted user info - email:', email, 'name:', name);
    console.log('Using SAML config:', samlConfig ? { id: samlConfig.id, name: samlConfig.saml_name, tenant_id: samlConfig.tenant_id } : 'none');

    // Check if user exists
    const { rows: existingUsers } = await pool.query(
      'SELECT id, email, name, status, role FROM users WHERE email = $1',
      [email]
    );

    console.log('Existing users found:', existingUsers.length);

    let user;
    if (existingUsers.length === 0) {
      // Create new user
      console.log('Creating new user...');
      const { rows: newUsers } = await pool.query(
        'INSERT INTO users (name, email, password, role, created_at, last_login_time) VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING id, email, name, status, role',
        [name, email, '', 'standard'] // Empty password for SAML users, default role
      );
      user = newUsers[0];
      console.log('User created successfully:', user.id);
    } else {
      // Update existing user's last login time
      user = existingUsers[0];
      console.log('Existing user found:', user.id, 'status:', user.status);
      if (user.status === 'blocked') {
        console.error('Account is blocked');
        return res.redirect('https://userly-pro.vercel.app/login?blocked=true&reason=account_locked');
      }
      await pool.query(
        'UPDATE users SET last_login_time = NOW() WHERE id = $1',
        [user.id]
      );
    }

    // Store tenant-specific Graph API credentials in the token for per-tenant Graph API access
    const tenantGraphCreds = samlConfig && samlConfig.graph_api_enabled ? {
      tenantId: samlConfig.tenant_id,
      clientId: samlConfig.client_id,
      clientSecret: samlConfig.client_secret,
      graphApiEnabled: samlConfig.graph_api_enabled,
      securityGroupId: samlConfig.security_group_id
    } : null;

    // Generate short-lived JWT token (15 min) for SAML users
    console.log('Generating JWT token with tenant info...');
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role || 'standard',
        authType: 'saml',
        samlConfigId: samlConfig ? samlConfig.id : null,
        tenantGraphCreds: tenantGraphCreds
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '15m' }
    );

    // Generate refresh token (24h) with tenant info
    const now = Date.now();
    const refreshToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        authType: 'saml_refresh',
        authTime: now,
        samlConfigId: samlConfig ? samlConfig.id : null,
        tenantGraphCreds: tenantGraphCreds
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Register session for IdP-initiated SLO tracking
    registerUserSession(user.id, token);
    registerUserSession(user.id, refreshToken);

    // Save sessions to database for Graph API polling
    try {
      await pool.query(
        `INSERT INTO user_sessions (user_id, token, auth_type, is_active)
         VALUES ($1, $2, 'saml', true),
                ($1, $3, 'saml', true)
         ON CONFLICT (token) DO UPDATE SET is_active = true`,
        [user.id, token, refreshToken]
      );
    } catch (dbError) {
      console.error('Failed to save user session to DB:', dbError);
    }

    console.log('JWT token generated successfully (15min expiry)');

    // Redirect to frontend with token and refresh token
    const frontendUrl = 'https://userly-pro.vercel.app';
    const redirectUrl = `${frontendUrl}/auth/callback?token=${token}&refreshToken=${refreshToken}&expiresIn=900`;
    
    console.log('Redirecting to:', redirectUrl);
    res.redirect(redirectUrl);
  } catch (error) {
    console.error('SAML user handling error:', error);
    console.error('Error stack:', error.stack);
    const errorMsg = encodeURIComponent(error.message || 'Unknown error');
    res.redirect(`https://userly-pro.vercel.app/login?error=user_handling_failed&details=${errorMsg}`);
  }
}

// Fallback GET handler for direct visits
router.get('/acs', (req, res) => {
  res.redirect('https://userly-pro.vercel.app/login');
});

const zlib = require('zlib');

// Build SAML LogoutRequest XML
function buildLogoutRequestXml(config, nameID) {
  const id = '_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  const issueInstant = new Date().toISOString();
  const issuer = `userly-${config.id}`;
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="${id}"
                     Version="2.0"
                     IssueInstant="${issueInstant}"
                     Destination="${config.idp_slo_url}">
  <saml:Issuer>${issuer}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameID || ''}</saml:NameID>
</samlp:LogoutRequest>`;
}

// Build logout URL with proper SAML LogoutRequest
function buildLogoutUrl(config, nameID) {
  if (!config.idp_slo_url) {
    return null;
  }
  
  // Generate SAML LogoutRequest XML
  const logoutRequestXml = buildLogoutRequestXml(config, nameID);
  console.log('Generated LogoutRequest:', logoutRequestXml);
  
  // Deflate and base64 encode the request
  const deflated = zlib.deflateRawSync(Buffer.from(logoutRequestXml, 'utf8'));
  const encodedRequest = deflated.toString('base64');
  
  // Build URL with SAMLRequest parameter
  const logoutUrl = new URL(config.idp_slo_url);
  logoutUrl.searchParams.append('SAMLRequest', encodedRequest);
  logoutUrl.searchParams.append('RelayState', 'https://userly-pro.vercel.app/login?logout=success');
  
  return logoutUrl.toString();
}

// SP-initiated Single Logout endpoint
// Called by frontend when user clicks logout
router.get('/logout/:id', async (req, res) => {
  try {
    const requestedId = req.params.id;
    console.log('SLO requested for ID:', requestedId);
    console.log('Current samlConfigs count:', samlConfigs.length);
    console.log('Available IDs:', samlConfigs.map(c => c.id));

    // Use loose equality to handle both string and number IDs (PostgreSQL returns BIGINT as string)
    let config = samlConfigs.find(c => c.id == requestedId);

    // If config not in memory, try reloading from DB (server may have restarted)
    if (!config) {
      console.log('Config not in memory, reloading from DB...');
      await loadSamlConfigsFromDb();
      config = samlConfigs.find(c => c.id == requestedId);
      console.log('After reload - configs count:', samlConfigs.length);
      console.log('After reload - available IDs:', samlConfigs.map(c => c.id));
    }

    if (!config) {
      console.log('Config not in memory, trying direct DB query...');
      // Direct DB lookup as final fallback
      try {
        const { rows } = await pool.query(
          'SELECT * FROM saml_configs WHERE id = $1',
          [requestedId]
        );
        if (rows.length > 0) {
          console.log('Found config in DB via direct query:', rows[0].id);
          config = rows[0];
        }
      } catch (dbError) {
        console.error('Direct DB query failed:', dbError);
      }
    }

    if (!config) {
      console.log('Config still not found after all attempts');
      return res.status(404).json({ message: 'SAML configuration not found' });
    }

    if (!config.idp_slo_url) {
      return res.status(400).json({ message: 'SLO not configured for this provider' });
    }

    // Get email/NameID from query param (passed by frontend)
    const nameID = req.query.nameID;

    // Build and redirect to IdP logout URL
    const logoutUrl = buildLogoutUrl(config, nameID);
    console.log('Redirecting to IdP logout:', logoutUrl);

    res.redirect(logoutUrl);
  } catch (error) {
    console.error('SAML logout error:', error);
    res.status(500).json({ message: 'Logout failed', error: error.message });
  }
});

// Parse SAML LogoutRequest from IdP
async function parseLogoutRequest(samlRequest) {
  try {
    // Decode base64 + inflate
    const buffer = Buffer.from(samlRequest, 'base64');
    const inflated = zlib.inflateRawSync(buffer);
    const xml = inflated.toString('utf8');
    console.log('Received LogoutRequest XML:', xml.substring(0, 500));

    // Parse XML
    const parser = new xml2js.Parser({ explicitArray: false });
    const result = await parser.parseStringPromise(xml);

    const logoutRequest = result['samlp:LogoutRequest'] || result.LogoutRequest;
    if (!logoutRequest) {
      throw new Error('Invalid LogoutRequest');
    }

    // Extract NameID (the user being logged out)
    const nameID = logoutRequest['saml:NameID'] || logoutRequest.NameID;
    const issuer = logoutRequest['saml:Issuer'] || logoutRequest.Issuer;

    return {
      id: logoutRequest.$.ID,
      issuer: typeof issuer === 'string' ? issuer : issuer?._,
      nameID: typeof nameID === 'string' ? nameID : nameID?._,
      destination: logoutRequest.$.Destination
    };
  } catch (error) {
    console.error('Failed to parse LogoutRequest:', error);
    return null;
  }
}

// Build SAML LogoutResponse XML
function buildLogoutResponse(inResponseTo, destination, status = 'urn:oasis:names:tc:SAML:2.0:status:Success') {
  const id = '_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  const issueInstant = new Date().toISOString();

  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="${id}"
                      InResponseTo="${inResponseTo}"
                      Version="2.0"
                      IssueInstant="${issueInstant}"
                      Destination="${destination}">
  <saml:Issuer>https://userly-341i.onrender.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="${status}"/>
  </samlp:Status>
</samlp:LogoutResponse>`;
}

// IdP-initiated Single Logout endpoint (receives logout from IdP)
router.post('/slo', async (req, res) => {
  console.log('IdP-initiated SLO received:', req.body);

  const { SAMLRequest, SAMLResponse, RelayState } = req.body;

  // Handle LogoutRequest from IdP
  if (SAMLRequest) {
    const logoutData = await parseLogoutRequest(SAMLRequest);
    if (!logoutData) {
      return res.status(400).send('Invalid LogoutRequest');
    }

    console.log('IdP-initiated logout for user:', logoutData.nameID);

    // Find user in database and invalidate their sessions
    try {
      const { rows } = await pool.query(
        'SELECT id, email FROM users WHERE email = $1',
        [logoutData.nameID]
      );

      if (rows.length > 0) {
        const user = rows[0];
        console.log('Invalidating all sessions for user:', user.email);

        // Blacklist all tokens for this user - they will be rejected on next API call
        invalidateUserSessions(user.id);
      } else {
        console.log('User not found in database:', logoutData.nameID);
      }
    } catch (error) {
      console.error('Database error during SLO:', error);
    }

    // Build and return LogoutResponse
    const logoutResponse = buildLogoutResponse(logoutData.id, logoutData.issuer);
    console.log('Sending LogoutResponse');

    res.set('Content-Type', 'application/xml');
    return res.send(logoutResponse);
  }

  // Handle LogoutResponse from IdP (response to our logout request)
  if (SAMLResponse) {
    console.log('Received LogoutResponse from IdP');
    // Parse and validate if needed
    return res.redirect('https://userly-pro.vercel.app/login?logout=success');
  }

  res.status(400).send('Invalid SLO request');
});

// GET handler for SLO (Entra uses GET for logout requests/responses)
router.get('/slo', async (req, res) => {
  console.log('SLO GET received:', req.query);

  const { SAMLRequest, SAMLResponse, RelayState } = req.query;

  // Handle LogoutRequest from IdP
  if (SAMLRequest) {
    const logoutData = await parseLogoutRequest(SAMLRequest);
    if (!logoutData) {
      return res.redirect('https://userly-pro.vercel.app/login?error=invalid_slo');
    }

    console.log('IdP-initiated logout (GET) for user:', logoutData.nameID);

    // Invalidate user sessions
    try {
      const { rows } = await pool.query(
        'SELECT id, email FROM users WHERE email = $1',
        [logoutData.nameID]
      );
      if (rows.length > 0) {
        invalidateUserSessions(rows[0].id);
      }
    } catch (error) {
      console.error('Database error during SLO GET:', error);
    }

    // Build LogoutResponse and redirect back to IdP
    const logoutResponse = buildLogoutResponse(logoutData.id, logoutData.issuer);
    const deflated = zlib.deflateRawSync(Buffer.from(logoutResponse, 'utf8'));
    const encodedResponse = deflated.toString('base64');

    // Determine where to send the response (usually back to IdP)
    const idpConfig = samlConfigs.find(c => c.idp_entity_id === logoutData.issuer);
    const sloUrl = idpConfig?.idp_slo_url || logoutData.destination;

    if (sloUrl && sloUrl !== 'https://userly-341i.onrender.com') {
      // Send response back to IdP
      const responseUrl = new URL(sloUrl);
      responseUrl.searchParams.append('SAMLResponse', encodedResponse);
      if (RelayState) responseUrl.searchParams.append('RelayState', RelayState);

      return res.redirect(responseUrl.toString());
    }

    // If no return URL, just redirect to login
    return res.redirect('https://userly-pro.vercel.app/login?logout=success');
  }

  // Handle LogoutResponse from IdP
  if (SAMLResponse) {
    console.log('Received LogoutResponse from IdP (GET)');
    return res.redirect('https://userly-pro.vercel.app/login?logout=success');
  }

  res.redirect('https://userly-pro.vercel.app/login?error=invalid_slo');
});

module.exports = router;
