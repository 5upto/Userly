const https = require('https');
const { pool } = require('../config/database');

// OIDC configuration cache
let oidcConfigs = [];

// Store strategies by config ID
const strategies = {};

// Session tracking for OIDC: userId -> Set of active tokens
const oidcUserSessions = new Map();

// Register a token for a user session (called after successful OIDC login)
function registerOidcSession(userId, token) {
  if (!oidcUserSessions.has(userId)) {
    oidcUserSessions.set(userId, new Set());
  }
  oidcUserSessions.get(userId).add(token);
  console.log('Registered OIDC session for user:', userId);
}

// Invalidate all tokens for a user
function invalidateOidcSessions(userId) {
  const tokens = oidcUserSessions.get(userId);
  if (tokens) {
    const { blacklistToken } = require('./tokenBlacklist');
    tokens.forEach(token => blacklistToken(token));
    oidcUserSessions.delete(userId);
    console.log('Invalidated all OIDC sessions for user:', userId);
  }
}

// Discover OIDC configuration from issuer's .well-known endpoint
async function discoverOidcConfig(issuerUrl) {
  return new Promise((resolve, reject) => {
    const wellKnownUrl = `${issuerUrl.replace(/\/$/, '')}/.well-known/openid-configuration`;
    
    const options = {
      hostname: new URL(wellKnownUrl).hostname,
      path: new URL(wellKnownUrl).pathname + new URL(wellKnownUrl).search,
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const config = JSON.parse(data);
            resolve({
              authorization_endpoint: config.authorization_endpoint,
              token_endpoint: config.token_endpoint,
              userinfo_endpoint: config.userinfo_endpoint,
              jwks_uri: config.jwks_uri,
              end_session_endpoint: config.end_session_endpoint
            });
          } else {
            reject(new Error(`Failed to discover OIDC config: ${res.statusCode}`));
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// Validate OIDC configuration by testing the discovery endpoint
async function validateOidcConfig(config) {
  try {
    const discovery = await discoverOidcConfig(config.issuer_url);
    
    // Validate required fields
    if (!discovery.authorization_endpoint || !discovery.token_endpoint) {
      return { valid: false, error: 'Missing required endpoints in discovery' };
    }

    return { valid: true, discovery };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

// Get OIDC config by ID
function getOidcConfigById(id) {
  return oidcConfigs.find(c => c.id === parseInt(id));
}

// Get OIDC config by email domain
function getOidcConfigByDomain(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return null;

  for (const config of oidcConfigs) {
    if (!config.enabled) continue;
    
    if (config.allowed_domains) {
      const domains = config.allowed_domains.split(',').map(d => d.trim().toLowerCase());
      if (domains.includes(domain) || domains.includes(email.toLowerCase())) {
        return config;
      }
    }
  }
  return null;
}

// Load OIDC configs from database
async function loadOidcConfigsFromDb() {
  try {
    console.log('Loading OIDC configurations from database...');
    const { rows } = await pool.query(
      'SELECT * FROM oidc_configs ORDER BY created_at DESC'
    );

    if (rows && rows.length > 0) {
      console.log(`Found ${rows.length} OIDC configuration(s) in database`);
      oidcConfigs = rows.map(row => ({
        id: row.id,
        oidc_name: row.oidc_name,
        allowed_domains: row.allowed_domains,
        issuer_url: row.issuer_url,
        client_id: row.client_id,
        client_secret: row.client_secret,
        callback_url: row.callback_url,
        scope: row.scope || 'openid profile email',
        response_type: row.response_type || 'code',
        enabled: row.enabled !== false,
        created_at: row.created_at
      }));
      console.log('OIDC configurations loaded successfully');
    } else {
      console.log('No OIDC configurations found in database');
    }
  } catch (error) {
    console.error('Failed to load OIDC configs from database:', error);
  }
}

// Refresh OIDC configs from database
async function refreshOidcConfigs() {
  await loadOidcConfigsFromDb();
}

// Get all OIDC configs
function getAllOidcConfigs() {
  return oidcConfigs;
}

// Add or update OIDC config in memory
function updateOidcConfigInMemory(config) {
  const existingIndex = oidcConfigs.findIndex(c => c.id === config.id);
  if (existingIndex >= 0) {
    oidcConfigs[existingIndex] = config;
  } else {
    oidcConfigs.push(config);
  }
}

// Remove OIDC config from memory
function removeOidcConfigFromMemory(id) {
  oidcConfigs = oidcConfigs.filter(c => c.id !== parseInt(id));
}

// Get user info from OIDC userinfo endpoint
async function getUserInfo(accessToken, userinfoEndpoint) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: new URL(userinfoEndpoint).hostname,
      path: new URL(userinfoEndpoint).pathname + new URL(userinfoEndpoint).search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`Failed to get user info: ${res.statusCode}`));
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// Exchange authorization code for tokens
async function exchangeCodeForToken(code, config, discovery, redirectUri) {
  return new Promise((resolve, reject) => {
    console.log('Exchanging code for token with redirect_uri:', redirectUri || config.callback_url);
    const postData = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri || config.callback_url,
      client_id: config.client_id,
      client_secret: config.client_secret
    }).toString();

    const options = {
      hostname: new URL(discovery.token_endpoint).hostname,
      path: new URL(discovery.token_endpoint).pathname + new URL(discovery.token_endpoint).search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`Failed to exchange code for token: ${res.statusCode}`));
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

module.exports = {
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
  invalidateOidcSessions,
  oidcUserSessions
};
