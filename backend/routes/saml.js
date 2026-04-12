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

// Function to create or retrieve SAML strategy for a given config
const getSamlStrategy = (config) => {
  const strategyName = `saml-${config.id}`;
  
  if (strategies[config.id]) {
    return strategies[config.id];
  }

  const strategy = new SamlStrategy(
    {
      name: strategyName,
      entryPoint: config.idp_sso_url,
      issuer: `userly-${config.id}`,
      cert: config.idp_certificate,
      callbackUrl: 'https://userly-pro.vercel.app/api/saml/acs',
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

  passport.use(strategy);
  strategies[config.id] = strategy;
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

// Create or update SAML configuration
router.post('/config', authenticateToken, upload.single('metadataFile'), async (req, res) => {
  try {
    const { samlName, allowedDomains, issuerUrl, idpSsoUrl, idpCertificate } = req.body;

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
  const acsUrl = 'https://userly-pro.vercel.app/api/saml/acs';
  const sloUrl = 'https://userly-pro.vercel.app/api/saml/slo';

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
    const config = samlConfigs.find(c => c.id === parseInt(req.params.id));
    
    if (!config) {
      return res.status(404).json({ message: 'SAML configuration not found' });
    }

    const strategy = getSamlStrategy(config);
    
    // Set RelayState to redirect back to frontend after authentication
    const relayState = 'https://userly-pro.vercel.app/auth/callback';
    
    console.log('Generating SAML request for config:', config.id, config.saml_name);
    console.log('IdP SSO URL:', config.idp_sso_url);
    
    // Generate SAML request using the strategy's internal method
    strategy._generateAuthorizeRequest(
      req,
      (err, requestUrl) => {
        if (err) {
          console.error('Error generating SAML request:', err);
          return res.status(500).json({ message: 'Failed to generate SAML request', error: err.message });
        }
        
        console.log('Generated SAML request URL:', requestUrl);
        
        // Append RelayState to the URL
        const separator = requestUrl.includes('?') ? '&' : '?';
        const finalUrl = `${requestUrl}${separator}RelayState=${encodeURIComponent(relayState)}`;
        
        console.log('Redirecting to IdP with RelayState:', finalUrl);
        res.redirect(finalUrl);
      },
      relayState
    );
  } catch (error) {
    console.error('SAML login initiation error:', error);
    res.status(500).json({ message: 'SAML login initiation failed', error: error.message });
  }
});

// SAML ACS (Assertion Consumer Service) endpoint - GET handler for HTTP-Redirect binding
router.get('/acs', async (req, res) => {
  try {
    const SAMLResponse = req.query.SAMLResponse;
    const RelayState = req.query.RelayState;

    console.log('SAML ACS received GET request (HTTP-Redirect binding)');
    console.log('SAMLResponse present:', !!SAMLResponse);
    console.log('RelayState:', RelayState);

    // If no SAMLResponse, redirect to login (direct visit)
    if (!SAMLResponse) {
      console.log('No SAMLResponse, redirecting to login');
      return res.redirect('https://userly-pro.vercel.app/login');
    }

    // Find the SAML config that matches this response
    console.log('Available SAML configs:', samlConfigs.length);
    if (samlConfigs.length === 0) {
      console.error('No SAML configuration found');
      return res.status(400).json({ message: 'No SAML configuration found' });
    }

    // Use the first config (in production, you'd need to match the correct config)
    const config = samlConfigs[0];
    console.log('Using SAML config:', config.id, config.saml_name);
    const strategy = getSamlStrategy(config);

    // Manually validate the SAML response (for HTTP-Redirect binding, response is base64 encoded in query param)
    console.log('Validating SAML response (HTTP-Redirect binding)...');
    const { profile } = await new Promise((resolve, reject) => {
      strategy._validateRedirectResponse(req.query, (err, profile) => {
        if (err) {
          console.error('SAML validation error:', err);
          reject(err);
        }
        else {
          console.log('SAML validation successful, profile:', profile);
          resolve({ profile });
        }
      });
    });

    // Extract user information from SAML profile
    const email = profile.nameID || profile.email;
    const name = profile.displayName || profile.name || email.split('@')[0];

    console.log('Extracted user info - email:', email, 'name:', name);

    // Check if user exists
    const { rows: existingUsers } = await pool.query(
      'SELECT id, email, name, status FROM users WHERE email = $1',
      [email]
    );

    console.log('Existing users found:', existingUsers.length);

    let user;
    if (existingUsers.length === 0) {
      // Create new user
      console.log('Creating new user...');
      const { rows: newUsers } = await pool.query(
        'INSERT INTO users (name, email, password, created_at, last_login_time) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, email, name, status',
        [name, email, ''] // Empty password for SAML users
      );
      user = newUsers[0];
      console.log('User created successfully:', user.id);
    } else {
      // Update existing user's last login time
      user = existingUsers[0];
      console.log('Existing user found:', user.id, 'status:', user.status);
      if (user.status === 'blocked') {
        console.error('Account is blocked');
        return res.status(403).json({ message: 'Account is blocked' });
      }
      await pool.query(
        'UPDATE users SET last_login_time = NOW() WHERE id = $1',
        [user.id]
      );
    }

    // Generate JWT token
    console.log('Generating JWT token...');
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    console.log('JWT token generated successfully');

    // Redirect to frontend with token
    const frontendUrl = 'https://userly-pro.vercel.app';
    const redirectUrl = RelayState || `${frontendUrl}/auth/callback?token=${token}`;
    
    // If RelayState is provided, append the token as query param
    const finalRedirectUrl = redirectUrl.includes('?') 
      ? `${redirectUrl}&token=${token}`
      : `${redirectUrl}?token=${token}`;

    console.log('Redirecting to:', finalRedirectUrl);
    res.redirect(finalRedirectUrl);
  } catch (error) {
    console.error('SAML ACS error (GET):', error);
    res.status(500).json({ message: 'SAML authentication failed', error: error.message });
  }
});

// SAML ACS (Assertion Consumer Service) endpoint - POST handler for SAML responses
router.post('/acs', async (req, res) => {
  try {
    console.log('SAML ACS received POST request');
    const SAMLResponse = req.body.SAMLResponse;
    const RelayState = req.body.RelayState;

    console.log('SAMLResponse present:', !!SAMLResponse);
    console.log('RelayState:', RelayState);

    if (!SAMLResponse) {
      console.error('SAMLResponse missing from request');
      return res.status(400).json({ message: 'SAMLResponse is required' });
    }

    // Find the SAML config that matches this response
    // In production, you might need to identify the config based on the issuer or other metadata
    console.log('Available SAML configs:', samlConfigs.length);
    if (samlConfigs.length === 0) {
      console.error('No SAML configuration found');
      return res.status(400).json({ message: 'No SAML configuration found' });
    }

    // Use the first config (in production, you'd need to match the correct config)
    const config = samlConfigs[0];
    console.log('Using SAML config:', config.id, config.saml_name);
    const strategy = getSamlStrategy(config);

    // Manually validate the SAML response
    console.log('Validating SAML response...');
    const { profile } = await new Promise((resolve, reject) => {
      strategy._validatePostResponse(req.body, (err, profile) => {
        if (err) {
          console.error('SAML validation error:', err);
          reject(err);
        }
        else {
          console.log('SAML validation successful, profile:', profile);
          resolve({ profile });
        }
      });
    });

    // Extract user information from SAML profile
    const email = profile.nameID || profile.email;
    const name = profile.displayName || profile.name || email.split('@')[0];

    console.log('Extracted user info - email:', email, 'name:', name);

    // Check if user exists
    const { rows: existingUsers } = await pool.query(
      'SELECT id, email, name, status FROM users WHERE email = $1',
      [email]
    );

    console.log('Existing users found:', existingUsers.length);

    let user;
    if (existingUsers.length === 0) {
      // Create new user
      console.log('Creating new user...');
      const { rows: newUsers } = await pool.query(
        'INSERT INTO users (name, email, password, created_at, last_login_time) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, email, name, status',
        [name, email, ''] // Empty password for SAML users
      );
      user = newUsers[0];
      console.log('User created successfully:', user.id);
    } else {
      // Update existing user's last login time
      user = existingUsers[0];
      console.log('Existing user found:', user.id, 'status:', user.status);
      if (user.status === 'blocked') {
        console.error('Account is blocked');
        return res.status(403).json({ message: 'Account is blocked' });
      }
      await pool.query(
        'UPDATE users SET last_login_time = NOW() WHERE id = $1',
        [user.id]
      );
    }

    // Generate JWT token
    console.log('Generating JWT token...');
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    console.log('JWT token generated successfully');

    // Redirect to frontend with token
    const frontendUrl = 'https://userly-pro.vercel.app';
    const redirectUrl = RelayState || `${frontendUrl}/auth/callback?token=${token}`;
    
    // If RelayState is provided, append the token as query param
    const finalRedirectUrl = redirectUrl.includes('?') 
      ? `${redirectUrl}&token=${token}`
      : `${redirectUrl}?token=${token}`;

    console.log('Redirecting to:', finalRedirectUrl);
    res.redirect(finalRedirectUrl);
  } catch (error) {
    console.error('SAML ACS error:', error);
    res.status(500).json({ message: 'SAML authentication failed', error: error.message });
  }
});

// SAML SLO (Single Logout) endpoint
router.get('/slo', (req, res) => {
  // Handle single logout
  res.send('SAML SLO endpoint');
});

module.exports = router;
