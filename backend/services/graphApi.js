const https = require('https');
const { blacklistToken } = require('../middleware/auth');
const { pool } = require('../config/database');

// Microsoft Graph API configuration
const GRAPH_CLIENT_ID = process.env.GRAPH_CLIENT_ID;
const GRAPH_CLIENT_SECRET = process.env.GRAPH_CLIENT_SECRET;
const GRAPH_TENANT_ID = process.env.GRAPH_TENANT_ID;

let accessToken = null;
let tokenExpiry = 0;

// Get access token for Microsoft Graph using client credentials
async function getGraphAccessToken() {
  // Return cached token if still valid
  if (accessToken && Date.now() < tokenExpiry - 60000) {
    return accessToken;
  }

  if (!GRAPH_CLIENT_ID || !GRAPH_CLIENT_SECRET || !GRAPH_TENANT_ID) {
    console.log('Graph API credentials not configured, skipping user status checks');
    return null;
  }

  return new Promise((resolve, reject) => {
    const postData = new URLSearchParams({
      client_id: GRAPH_CLIENT_ID,
      client_secret: GRAPH_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials'
    }).toString();

    const options = {
      hostname: 'login.microsoftonline.com',
      path: `/${GRAPH_TENANT_ID}/oauth2/v2.0/token`,
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
          const response = JSON.parse(data);
          if (response.access_token) {
            accessToken = response.access_token;
            tokenExpiry = Date.now() + (response.expires_in * 1000);
            console.log('Graph API token acquired');
            resolve(accessToken);
          } else {
            console.error('Failed to get Graph token:', response);
            reject(new Error('Failed to acquire Graph token'));
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

// Check user status in Entra via Graph API
async function checkUserStatusInEntra(email) {
  const token = await getGraphAccessToken();
  if (!token) return null;

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${encodeURIComponent(email)}?$select=accountEnabled`,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 404) {
            resolve({ exists: false, blocked: true });
          } else if (res.statusCode === 200) {
            const user = JSON.parse(data);
            resolve({
              exists: true,
              blocked: !user.accountEnabled
            });
          } else {
            console.error(`Graph API error: ${res.statusCode}`, data);
            resolve(null);
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', (err) => {
      console.error('Graph API request error:', err);
      resolve(null);
    });
    req.end();
  });
}

// Check if user still has access to the application via security group
async function checkUserAppAccess(email, appClientId) {
  const token = await getGraphAccessToken();
  if (!token) return null;

  // First, get the user ID
  const userId = await getUserIdByEmail(email, token);
  if (!userId) return { hasAccess: false, reason: 'User not found' };

  // Get the service principal for this app
  const servicePrincipalId = await getServicePrincipalId(appClientId, token);
  if (!servicePrincipalId) return { hasAccess: true }; // Can't verify, assume access

  // Check if user has app role assignment for this app
  const hasAppAssignment = await checkAppRoleAssignment(userId, servicePrincipalId, token);

  return {
    hasAccess: hasAppAssignment,
    reason: hasAppAssignment ? null : 'User removed from security group'
  };
}

async function getUserIdByEmail(email, accessToken) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${encodeURIComponent(email)}?$select=id`,
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
            const user = JSON.parse(data);
            resolve(user.id);
          } else {
            resolve(null);
          }
        } catch (e) {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.end();
  });
}

async function getServicePrincipalId(appId, accessToken) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/servicePrincipals?$filter=appId eq '${appId}'&$select=id`,
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
            const response = JSON.parse(data);
            resolve(response.value?.[0]?.id || null);
          } else {
            resolve(null);
          }
        } catch (e) {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.end();
  });
}

async function checkAppRoleAssignment(userId, servicePrincipalId, accessToken) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${userId}/appRoleAssignments?$filter=resourceId eq ${servicePrincipalId}`,
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
            const response = JSON.parse(data);
            // If user has any app role assignments for this app, they have access
            resolve(response.value && response.value.length > 0);
          } else {
            resolve(true); // On error, assume access to avoid lockouts
          }
        } catch (e) {
          resolve(true);
        }
      });
    });

    req.on('error', () => resolve(true));
    req.end();
  });
}

// Poll all SAML users and invalidate sessions of blocked/revoked users
async function pollUserStatus() {
  try {
    // Get all active SAML users from our database
    const { rows: activeUsers } = await pool.query(
      `SELECT DISTINCT u.id, u.email, u.status
       FROM users u
       JOIN user_sessions us ON u.id = us.user_id
       WHERE us.auth_type = 'saml'
       AND us.is_active = true
       AND us.created_at > NOW() - INTERVAL '24 hours'`
    );

    if (activeUsers.length === 0) return;

    console.log(`Polling ${activeUsers.length} active SAML users against Entra...`);

    // Get SAML app client ID from env
    const samlAppClientId = process.env.SAML_APP_CLIENT_ID;

    for (const user of activeUsers) {
      // Check 1: Is user blocked/disabled in Entra?
      const entraStatus = await checkUserStatusInEntra(user.email);

      if (entraStatus && entraStatus.blocked) {
        console.log(`User ${user.email} is BLOCKED in Entra, invalidating session`);
        await invalidateUserSessions(user.id, 'User blocked in Entra ID');
        continue;
      }

      // Check 2: Does user still have app access (security group membership)?
      if (samlAppClientId) {
        const appAccess = await checkUserAppAccess(user.email, samlAppClientId);

        if (appAccess && !appAccess.hasAccess) {
          console.log(`User ${user.email} removed from security group, invalidating session`);
          await invalidateUserSessions(user.id, appAccess.reason || 'User removed from security group');
          continue;
        }
      }
    }
  } catch (error) {
    console.error('Error polling user status:', error);
  }
}

// Invalidate all sessions for a user
async function invalidateUserSessions(userId, reason) {
  try {
    // Get user's active tokens
    const { rows: sessions } = await pool.query(
      `SELECT token FROM user_sessions
       WHERE user_id = $1 AND auth_type = 'saml' AND is_active = true`,
      [userId]
    );

    // Blacklist all tokens
    for (const session of sessions) {
      blacklistToken(session.token);
    }

    // Mark sessions as inactive in DB
    await pool.query(
      `UPDATE user_sessions SET is_active = false, invalidated_at = NOW(),
       invalidated_reason = $2
       WHERE user_id = $1 AND auth_type = 'saml'`,
      [userId, reason]
    );

    // Also update local user status
    await pool.query(
      `UPDATE users SET status = 'blocked' WHERE id = $1`,
      [userId]
    );

    console.log(`Invalidated ${sessions.length} sessions for user ${userId}: ${reason}`);
  } catch (error) {
    console.error('Error invalidating user sessions:', error);
  }
}

// Start polling (every 2 minutes)
function startUserStatusPolling() {
  if (!GRAPH_CLIENT_ID || !GRAPH_CLIENT_SECRET || !GRAPH_TENANT_ID) {
    console.log('Graph API not configured. Set GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, GRAPH_TENANT_ID env vars');
    return;
  }

  console.log('Starting Entra user status polling (every 2 minutes)');

  // Run immediately on start
  pollUserStatus();

  // Then every 2 minutes
  setInterval(pollUserStatus, 2 * 60 * 1000);
}

module.exports = {
  startUserStatusPolling,
  checkUserStatusInEntra,
  checkUserAppAccess,
  pollUserStatus,
  invalidateUserSessions
};
