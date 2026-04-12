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
          'SELECT id, email, name, status FROM users WHERE email = $1',
          [email]
        );

        let user;
        if (existingUsers.length === 0) {
          // Create new user
          const { rows: newUsers } = await pool.query(
            'INSERT INTO users (name, email, password, created_at, last_login_time) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, email, name, status',
            [name, email, ''] // Empty password for SAML users
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

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Get all SAML configurations
router.get('/configs', authenticateToken, (req, res) => {
  res.json(samlConfigs);
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
router.post('/config', authenticateToken, upload.single('metadataFile'), async (req, res) => {
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
      idp_certificate: req.body.idpCertificate || idpCertificate,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    samlConfigs.push(config);
    res.status(201).json(config);
  } catch (error) {
    console.error('Error saving SAML config:', error);
    res.status(500).json({ message: 'Failed to save SAML configuration' });
  }
});

// Delete SAML configuration
router.delete('/config/:id', authenticateToken, (req, res) => {
  const id = parseInt(req.params.id);
  samlConfigs = samlConfigs.filter(config => config.id !== id);
  res.json({ message: 'Configuration deleted successfully' });
});

// Generate SAML metadata for service provider
router.get('/metadata/:id', authenticateToken, (req, res) => {
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
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${sloUrl}"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Content-Disposition', 'attachment; filename="saml-metadata.xml"');
  res.send(metadata);
});

// SAML login initiation endpoint
router.get('/login/:id', async (req, res) => {
  try {
    console.log('SAML login initiation request for ID:', req.params.id);
    console.log('Available configs:', samlConfigs.map(c => ({ id: c.id, name: c.saml_name })));
    
    const config = samlConfigs.find(c => c.id === parseInt(req.params.id));
    
    if (!config) {
      console.error('SAML configuration not found for ID:', req.params.id);
      return res.status(404).json({ message: 'SAML configuration not found' });
    }

    console.log('Initiating SAML login for config:', config.id, config.saml_name);
    console.log('IdP SSO URL:', config.idp_sso_url);
    
    // Get the strategy to generate the SAML request
    const strategy = getSamlStrategy(config);
    
    // Generate SAML request URL using the strategy's internal method
    strategy._generateAuthorizeRequest(
      req,
      (err, requestUrl) => {
        if (err) {
          console.error('Error generating SAML request:', err);
          return res.status(500).json({ message: 'Failed to generate SAML request', error: err.message });
        }
        
        console.log('Generated SAML request URL:', requestUrl);
        res.redirect(requestUrl);
      }
    );
  } catch (error) {
    console.error('SAML login initiation error:', error);
    res.status(500).json({ message: 'SAML login initiation failed', error: error.message });
  }
});

// SAML ACS (Assertion Consumer Service) endpoint - handles POST (HTTP-POST binding)
router.post('/acs', (req, res, next) => {
  console.log('SAML ACS received POST request');
  console.log('Request body keys:', Object.keys(req.body));
  console.log('SAMLResponse present:', !!req.body.SAMLResponse);
  console.log('RelayState:', req.body.RelayState);
  
  // Use the first available config for authentication
  if (samlConfigs.length === 0) {
    console.error('No SAML configuration found');
    return res.status(400).json({ message: 'No SAML configuration found' });
  }
  
  const config = samlConfigs[0];
  const strategyName = `saml-${config.id}`;
  
  console.log('Using strategy:', strategyName);
  
  passport.authenticate(strategyName, { 
    failureRedirect: 'https://userly-pro.vercel.app/login?error=auth_failed',
    failureFlash: true,
    session: false 
  }, (err, user, info) => {
    if (err) {
      console.error('Passport authentication error:', err);
      return res.redirect('https://userly-pro.vercel.app/login?error=passport_error');
    }
    if (!user) {
      console.error('No user returned from passport:', info);
      return res.redirect('https://userly-pro.vercel.app/login?error=no_user');
    }
    
    // Attach user to request for the next handler
    req.user = user;
    next();
  })(req, res, next);
}, async (req, res) => {
  try {
    console.log('SAML ACS callback received user:', req.user);
    
    const user = req.user;
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    const frontendUrl = 'https://userly-pro.vercel.app';
    const redirectUrl = `${frontendUrl}/auth/callback?token=${token}`;
    
    console.log('Redirecting to:', redirectUrl);
    res.redirect(redirectUrl);
  } catch (error) {
    console.error('SAML ACS callback error:', error);
    res.redirect('https://userly-pro.vercel.app/login?error=token_generation_failed');
  }
});

// Fallback GET handler for direct visits
router.get('/acs', (req, res) => {
  res.redirect('https://userly-pro.vercel.app/login');
});

// SAML SLO (Single Logout) endpoint
router.get('/slo', (req, res) => {
  // Handle single logout
  res.send('SAML SLO endpoint');
});

module.exports = router;
