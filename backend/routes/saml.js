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
const { authenticateToken, requireAdmin } = require('../middleware/auth');

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

// Load SAML configs from database on startup
const loadSamlConfigsFromDb = async () => {
  try {
    console.log('Loading SAML configurations from database...');
    const { rows } = await pool.query(
      'SELECT * FROM saml_configs ORDER BY created_at DESC'
    );
    
    if (rows && rows.length > 0) {
      console.log(`Found ${rows.length} SAML configuration(s) in database`);
      
      // Transform database rows to config objects
      samlConfigs = rows.map(row => ({
        id: row.id,
        saml_name: row.saml_name,
        allowed_domains: row.allowed_domains,
        issuer_url: row.issuer_url,
        idp_sso_url: row.idp_sso_url,
        idp_slo_url: row.idp_slo_url,
        idp_certificate: row.idp_certificate,
        created_at: row.created_at
      }));
      
      // Register each config's strategy with passport
      samlConfigs.forEach(config => {
        const strategy = getSamlStrategy(config);
        const strategyName = `saml-${config.id}`;
        passport.use(strategyName, strategy);
        console.log(`Registered SAML strategy: ${strategyName}`);
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
      logoutUrl: config.idp_slo_url || null,
      logoutCallbackUrl: 'https://userly-341i.onrender.com/api/saml/slo',
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
            return done(new Error('Account is blocked'), null);
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
router.get('/providers', (req, res) => {
  // Return minimal info needed for login page
  const providers = samlConfigs.map(c => ({
    id: c.id,
    saml_name: c.saml_name,
    allowed_domains: c.allowed_domains
  }));
  res.json(providers);
});

// Diagnostic endpoint to check SAML status (no auth required for debugging)
router.get('/status', (req, res) => {
  res.json({
    configsCount: samlConfigs.length,
    configs: samlConfigs.map(c => ({ id: c.id, name: c.saml_name, ssoUrl: c.idp_sso_url })),
    strategiesRegistered: Object.keys(strategies).length
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
    const { samlName, allowedDomains, issuerUrl, idpSsoUrl, idpCertificate } = req.body;
    console.log('Config name:', samlName);

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
        // Extract SingleLogoutService URL from metadata
        const sloService = parsedMetadata.EntityDescriptor?.IDPSSODescriptor?.[0]?.SingleLogoutService?.find(
          service => service['$']?.Binding?.includes('HTTP-Redirect')
        );
        if (sloService?.['$']?.Location) {
          req.body.idpSloUrl = sloService['$'].Location;
        }
        if (!idpCertificate && parsedMetadata.EntityDescriptor?.IDPSSODescriptor?.[0]?.KeyDescriptor?.[0]?.KeyInfo?.[0]?.X509Data?.[0]?.X509Certificate?.[0]) {
          req.body.idpCertificate = parsedMetadata.EntityDescriptor.IDPSSODescriptor[0].KeyDescriptor[0].KeyInfo[0].X509Data[0].X509Certificate[0];
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
      idp_slo_url: req.body.idpSloUrl || req.body.idpSloUrl,
      idp_certificate: req.body.idpCertificate || idpCertificate,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Save to database for persistence
    try {
      const { rows } = await pool.query(
        `INSERT INTO saml_configs (id, saml_name, allowed_domains, issuer_url, idp_sso_url, idp_slo_url, idp_certificate, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO UPDATE SET
           saml_name = EXCLUDED.saml_name,
           allowed_domains = EXCLUDED.allowed_domains,
           issuer_url = EXCLUDED.issuer_url,
           idp_sso_url = EXCLUDED.idp_sso_url,
           idp_slo_url = EXCLUDED.idp_slo_url,
           idp_certificate = EXCLUDED.idp_certificate,
           updated_at = NOW()
         RETURNING *`,
        [config.id, config.saml_name, config.allowed_domains, config.issuer_url, 
         config.idp_sso_url, config.idp_slo_url, config.idp_certificate, config.created_at]
      );
      console.log('SAML config saved to database:', rows[0].id);
    } catch (dbError) {
      console.error('Failed to save SAML config to database:', dbError);
      // Continue with in-memory only if DB fails
    }

    samlConfigs.push(config);
    
    // Register the SAML strategy with passport
    const strategy = getSamlStrategy(config);
    const strategyName = `saml-${config.id}`;
    passport.use(strategyName, strategy);
    console.log(`Registered new SAML strategy: ${strategyName}`);
    
    res.status(201).json(config);
  } catch (error) {
    console.error('Error saving SAML config:', error);
    res.status(500).json({ message: 'Failed to save SAML configuration' });
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
  
  // Remove from memory - handle both string and number IDs
  const initialLength = samlConfigs.length;
  samlConfigs = samlConfigs.filter(config => parseInt(config.id) !== id);
  console.log('Removed from memory:', initialLength - samlConfigs.length, 'configs');
  res.json({ message: 'Configuration deleted successfully' });
});

// Generate SAML metadata for service provider
router.get('/metadata/:id', (req, res) => {
  const config = samlConfigs.find(c => c.id === parseInt(req.params.id));
  
  if (!config) {
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
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sloUrl}" index="1"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${sloUrl}" index="2"/>
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
    console.log('Available configs:', samlConfigs.map(c => ({ id: c.id, name: c.saml_name })));
    
    const config = samlConfigs.find(c => c.id === parseInt(req.params.id));
    
    if (!config) {
      console.error('SAML configuration not found for ID:', req.params.id);
      return res.status(404).json({ message: 'SAML configuration not found' });
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
    
    // Use the first available config for authentication
    if (samlConfigs.length === 0) {
      console.error('No SAML configuration found - configs may have been lost on server restart');
      return res.redirect('https://userly-pro.vercel.app/login?error=no_saml_config');
    }
    
    const config = samlConfigs[0];
    const strategyName = `saml-${config.id}`;
    
    console.log('Using strategy:', strategyName);
    console.log('Config details:', { id: config.id, name: config.saml_name, ssoUrl: config.idp_sso_url });
    
    // Use passport-saml authentication
    passport.authenticate(strategyName, { 
      failureRedirect: 'https://userly-pro.vercel.app/login?error=auth_failed',
      failureFlash: true,
      session: false 
    }, (err, profile) => {
      if (err) {
        console.error('Passport authentication error:', err);
        console.error('Error type:', err.name);
        console.error('Error message:', err.message);
        const errorMsg = encodeURIComponent(err.message || 'Unknown error');
        return res.redirect(`https://userly-pro.vercel.app/login?error=passport_error&details=${errorMsg}`);
      }
      if (!profile) {
        console.error('No profile returned from passport');
        return res.redirect('https://userly-pro.vercel.app/login?error=no_profile');
      }
      
      console.log('SAML authentication successful, profile:', profile);
      
      // Handle user creation/update and token generation
      handleSamlUser(profile, res, config.id);
    })(req, res, next);
  } catch (error) {
    console.error('SAML ACS error:', error);
    console.error('Error stack:', error.stack);
    const errorMsg = encodeURIComponent(error.message || 'Unknown error');
    res.redirect(`https://userly-pro.vercel.app/login?error=acs_failed&details=${errorMsg}`);
  }
});

async function handleSamlUser(profile, res, configId) {
  try {
    const email = profile.nameID || profile.email;
    const name = profile.displayName || profile.name || email.split('@')[0];
    const nameID = profile.nameID;
    const sessionIndex = profile.sessionIndex;

    console.log('Extracted user info - email:', email, 'name:', name, 'sessionIndex:', sessionIndex);

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
        return res.redirect('https://userly-pro.vercel.app/login?error=account_blocked');
      }
      await pool.query(
        'UPDATE users SET last_login_time = NOW() WHERE id = $1',
        [user.id]
      );
    }

    // Generate JWT token with SAML auth method and config ID
    console.log('Generating JWT token...');
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        name: user.name, 
        role: user.role || 'standard',
        authMethod: 'saml',
        samlConfigId: configId,
        samlNameID: nameID,
        samlSessionIndex: sessionIndex
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    console.log('JWT token generated successfully with SAML metadata');

    // Redirect to frontend with token
    const frontendUrl = 'https://userly-pro.vercel.app';
    const redirectUrl = `${frontendUrl}/auth/callback?token=${token}`;
    
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

// SAML SLO (Single Logout) endpoint - handles both IdP-initiated and LogoutResponse
router.get('/slo', handleSloRequest);
router.post('/slo', handleSloRequest);

async function handleSloRequest(req, res) {
  try {
    const samlRequest = req.body.SAMLRequest || req.query.SAMLRequest;
    const samlResponse = req.body.SAMLResponse || req.query.SAMLResponse;
    const relayState = req.body.RelayState || req.query.RelayState;

    console.log('SLO request received - SAMLRequest:', !!samlRequest, 'SAMLResponse:', !!samlResponse);

    // Get the first available config for handling SLO
    if (samlConfigs.length === 0) {
      console.error('No SAML configuration found for SLO');
      return res.redirect('https://userly-pro.vercel.app/login?error=slo_no_config');
    }

    const config = samlConfigs[0];
    const strategyName = `saml-${config.id}`;

    // Check if this is a LogoutResponse from IdP (SP-initiated logout flow)
    if (samlResponse) {
      console.log('Processing LogoutResponse from IdP');
      
      // Use passport-saml to validate the LogoutResponse
      passport.authenticate(strategyName, { session: false }, (err, user, info) => {
        if (err) {
          console.error('LogoutResponse validation error:', err);
          return res.redirect('https://userly-pro.vercel.app/login?error=logout_failed');
        }
        
        console.log('LogoutResponse processed successfully');
        // Redirect to login page - user is now logged out from both SP and IdP
        return res.redirect('https://userly-pro.vercel.app/login?message=logged_out');
      })(req, res, () => {
        // If we reach here, logout was successful
        return res.redirect('https://userly-pro.vercel.app/login?message=logged_out');
      });
      return;
    }

    // Check if this is a LogoutRequest from IdP (IdP-initiated logout flow)
    if (samlRequest) {
      console.log('Processing LogoutRequest from IdP (IdP-initiated logout)');
      
      // Parse and validate the LogoutRequest
      const SamlStrategy = require('passport-saml').Strategy;
      const strategy = passport._strategies[strategyName];
      
      if (!strategy) {
        console.error('SAML strategy not found:', strategyName);
        return res.status(500).send('SAML configuration error');
      }

      // Validate the LogoutRequest and extract NameID and SessionIndex
      strategy.validatePostRequest(req.body, async (err, logout) => {
        if (err) {
          console.error('LogoutRequest validation error:', err);
          return res.status(400).send('Invalid logout request');
        }

        console.log('LogoutRequest validated - NameID:', logout.nameID, 'SessionIndex:', logout.sessionIndex);

        try {
          // Find user by email (NameID) and revoke their session
          const { rows: users } = await pool.query(
            'SELECT id, email FROM users WHERE email = $1',
            [logout.nameID]
          );

          if (users.length > 0) {
            const user = users[0];
            // Insert revoked session record
            await pool.query(
              `INSERT INTO revoked_sessions (user_id, email, saml_session_index, reason)
               VALUES ($1, $2, $3, 'logout')`,
              [user.id, user.email, logout.sessionIndex || null]
            );
            console.log(`Session revoked for user ${user.email} (IdP-initiated logout)`);
          }
        } catch (dbError) {
          console.error('Error recording revoked session:', dbError);
          // Continue with logout even if DB recording fails
        }

        // Generate LogoutResponse to send back to IdP
        strategy.generateServiceProviderLogoutResponse(logout, (err, response) => {
          if (err) {
            console.error('Error generating LogoutResponse:', err);
            return res.status(500).send('Error processing logout');
          }

          console.log('LogoutResponse generated successfully');
          
          // Return the LogoutResponse to the IdP
          res.setHeader('Content-Type', 'text/html');
          res.send(`
            <form method="post" action="${config.idp_slo_url || config.idp_sso_url}" id="sloResponseForm">
              <input type="hidden" name="SAMLResponse" value="${Buffer.from(response).toString('base64')}" />
              ${relayState ? `<input type="hidden" name="RelayState" value="${relayState}" />` : ''}
            </form>
            <script>document.getElementById('sloResponseForm').submit();</script>
          `);
        });
      });
      return;
    }

    // No SAML data - just redirect to login
    console.log('No SAML data in SLO request, redirecting to login');
    res.redirect('https://userly-pro.vercel.app/login');
  } catch (error) {
    console.error('SLO endpoint error:', error);
    res.redirect('https://userly-pro.vercel.app/login?error=slo_error');
  }
}

// SP-initiated logout endpoint
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    console.log('Logout request received for user:', user.email, 'authMethod:', user.authMethod);

    // Check if user authenticated via SAML
    if (user.authMethod === 'saml' && user.samlConfigId && user.samlNameID) {
      // Record session revocation for this logout
      try {
        await pool.query(
          `INSERT INTO revoked_sessions (user_id, email, saml_session_index, reason)
           VALUES ($1, $2, $3, 'logout')`,
          [user.userId, user.email, user.samlSessionIndex || null]
        );
        console.log(`Session revocation recorded for user ${user.email} (SP-initiated logout)`);
      } catch (dbError) {
        console.error('Error recording session revocation:', dbError);
        // Continue with logout even if DB recording fails
      }

      const config = samlConfigs.find(c => c.id === parseInt(user.samlConfigId));
      
      if (!config || !config.idp_slo_url) {
        console.log('SAML config or SLO URL not available, performing local logout only');
        return res.json({ success: true, message: 'Local logout only - IdP SLO not configured' });
      }

      const strategyName = `saml-${config.id}`;
      const strategy = passport._strategies[strategyName];

      if (!strategy) {
        console.error('SAML strategy not found for logout:', strategyName);
        return res.status(500).json({ error: 'SAML configuration error' });
      }

      console.log('Initiating SP-initiated SLO to IdP:', config.idp_slo_url);

      // Generate LogoutRequest
      const logoutRequest = strategy.generateServiceProviderLogoutRequest({
        nameID: user.samlNameID,
        sessionIndex: user.samlSessionIndex
      });

      // Redirect to IdP SLO endpoint with the LogoutRequest
      const relayState = 'https://userly-pro.vercel.app/login?message=logged_out';
      const sloUrl = new URL(config.idp_slo_url);
      sloUrl.searchParams.append('SAMLRequest', Buffer.from(logoutRequest).toString('deflate').toString('base64'));
      sloUrl.searchParams.append('RelayState', relayState);

      console.log('Redirecting to IdP SLO endpoint:', sloUrl.toString());
      
      return res.json({
        success: true,
        sloInitiated: true,
        redirectUrl: sloUrl.toString()
      });
    }

    // Non-SAML user - just return success for local logout
    console.log('Non-SAML user, local logout only');
    return res.json({ success: true, message: 'Local logout successful' });
  } catch (error) {
    console.error('Logout endpoint error:', error);
    res.status(500).json({ error: 'Logout failed', message: error.message });
  }
});

// Helper function to revoke all sessions for a user (used when blocking users)
const revokeUserSessions = async (userId, email, reason = 'admin_action') => {
  try {
    await pool.query(
      `INSERT INTO revoked_sessions (user_id, email, reason)
       VALUES ($1, $2, $3)`,
      [userId, email, reason]
    );
    console.log(`All sessions revoked for user ${email} (reason: ${reason})`);
    return true;
  } catch (error) {
    console.error('Error revoking user sessions:', error);
    return false;
  }
};

module.exports = { router, revokeUserSessions };
