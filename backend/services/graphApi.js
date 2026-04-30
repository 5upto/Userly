const https = require('https');
const { blacklistToken } = require('../middleware/auth');
const { pool } = require('../config/database');

// Microsoft Graph API configuration (legacy single-tenant support)
const GRAPH_CLIENT_ID = process.env.GRAPH_CLIENT_ID;
const GRAPH_CLIENT_SECRET = process.env.GRAPH_CLIENT_SECRET;
const GRAPH_TENANT_ID = process.env.GRAPH_TENANT_ID;

let accessToken = null;
let tokenExpiry = 0;

// Multi-tenant token cache: tenantId -> { token, expiry }
const tenantTokenCache = new Map();

// Get access token for a specific tenant using stored credentials
async function getTenantGraphToken(tenantId, clientId, clientSecret) {
  if (!tenantId || !clientId || !clientSecret) {
    return null;
  }

  const cacheKey = `${tenantId}:${clientId}`;
  const cached = tenantTokenCache.get(cacheKey);

  // Return cached token if still valid (with 1 minute buffer)
  if (cached && Date.now() < cached.expiry - 60000) {
    return cached.token;
  }

  return new Promise((resolve, reject) => {
    const postData = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials'
    }).toString();

    const options = {
      hostname: 'login.microsoftonline.com',
      path: `/${tenantId}/oauth2/v2.0/token`,
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
            // Cache the token
            tenantTokenCache.set(cacheKey, {
              token: response.access_token,
              expiry: Date.now() + (response.expires_in * 1000)
            });
            console.log(`Graph API token acquired for tenant: ${tenantId}`);
            resolve(response.access_token);
          } else {
            console.error(`Failed to get Graph token for tenant ${tenantId}:`, response);
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

// Get Graph token for a specific SAML config
async function getGraphTokenForConfig(config) {
  // If config has tenant-specific credentials, use those
  if (config.graph_api_enabled && config.tenant_id && config.client_id && config.client_secret) {
    return getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
  }
  // Fall back to global env vars (legacy mode)
  return getGraphAccessToken();
}

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

// Check if user is currently a member of the security group (real-time)
async function checkUserGroupMembership(email, securityGroupId) {
  const token = await getGraphAccessToken();
  if (!token) return null;

  // First get user ID
  const userId = await getUserIdByEmail(email, token);
  if (!userId) return { isMember: false, reason: 'User not found' };

  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/groups/${encodeURIComponent(securityGroupId)}/members?$select=id&$top=500`,
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
          if (res.statusCode === 200) {
            const response = JSON.parse(data);
            const members = response.value || [];
            const isMember = members.some(m => m.id === userId);

            resolve({
              isMember: isMember,
              reason: isMember ? null : 'User not in security group'
            });
          } else if (res.statusCode === 404) {
            resolve({ isMember: false, reason: 'Group not found' });
          } else {
            console.error(`Group membership check error: ${res.statusCode}`, data);
            resolve({ isMember: true }); // Assume access on error
          }
        } catch (e) {
          console.error('Error parsing group membership:', e);
          resolve({ isMember: true }); // Assume access on error
        }
      });
    });

    req.on('error', (err) => {
      console.error('Group membership request error:', err);
      resolve({ isMember: true }); // Assume access on error
    });
    req.end();
  });
}

// Check if user was recently removed from the security group via audit logs
async function checkAuditLogsForGroupRemoval(email, securityGroupId) {
  const token = await getGraphAccessToken();
  if (!token) return null;

  // Check last 5 minutes of audit logs
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();

  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName%20eq%20'Remove%20member%20from%20group'%20and%20activityDateTime%20ge%20${encodeURIComponent(fiveMinutesAgo)}`,
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
          if (res.statusCode === 200) {
            const response = JSON.parse(data);
            const audits = response.value || [];

            // Check if any audit log entry matches this user and group
            const userRemoved = audits.some(audit => {
              const targetResources = audit.targetResources || [];
              const initiatedBy = audit.initiatedBy?.user || {};

              // Check if this is about our target group
              const isTargetGroup = targetResources.some(tr =>
                tr.id === securityGroupId &&
                tr.type === 'Group'
              );

              // Check if the removed user matches our email
              const isUserRemoved = targetResources.some(tr =>
                tr.type === 'User' &&
                tr.userPrincipalName?.toLowerCase() === email.toLowerCase()
              );

              return isTargetGroup && isUserRemoved;
            });

            resolve({
              wasRemoved: userRemoved,
              auditFound: audits.length > 0
            });
          } else {
            console.error(`Audit log API error: ${res.statusCode}`, data);
            resolve(null);
          }
        } catch (e) {
          console.error('Error parsing audit logs:', e);
          resolve(null);
        }
      });
    });

    req.on('error', (err) => {
      console.error('Audit log request error:', err);
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

  // Check 1: Direct app role assignment
  const servicePrincipalId = await getServicePrincipalId(appClientId, token);
  if (servicePrincipalId) {
    const hasAppAssignment = await checkAppRoleAssignment(userId, servicePrincipalId, token);
    if (!hasAppAssignment) {
      // Check 2: Was user recently removed from security group? (via audit logs)
      const securityGroupId = process.env.SAML_SECURITY_GROUP_ID;
      if (securityGroupId) {
        const auditCheck = await checkAuditLogsForGroupRemoval(email, securityGroupId);
        if (auditCheck?.wasRemoved) {
          console.log(`Audit log: User ${email} was removed from security group ${securityGroupId}`);
          return { hasAccess: false, reason: 'User removed from security group' };
        }
      }

      return { hasAccess: false, reason: 'User removed from security group' };
    }
  }

  return { hasAccess: true };
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
      path: `/v1.0/servicePrincipals?$filter=appId%20eq%20'${encodeURIComponent(appId)}'&$select=id`,
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
      path: `/v1.0/users/${encodeURIComponent(userId)}/appRoleAssignments?$filter=resourceId%20eq%20${encodeURIComponent(servicePrincipalId)}`,
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

// Poll for group removals via audit logs (more frequent)
async function pollAuditLogsForGroupRemovals() {
  const securityGroupId = process.env.SAML_SECURITY_GROUP_ID;
  if (!securityGroupId) return;

  try {
    // Check audit logs for recent group removals
    const removedUsers = await getRecentGroupRemovals(securityGroupId);

    if (removedUsers.length === 0) return;

    console.log(`Found ${removedUsers.length} users removed from security group in audit logs`);

    // For each removed user, invalidate their sessions
    for (const email of removedUsers) {
      // Find user in database
      const { rows: users } = await pool.query(
        'SELECT id FROM users WHERE LOWER(email) = LOWER($1)',
        [email]
      );

      if (users.length > 0) {
        const userId = users[0].id;
        console.log(`Invalidating sessions for removed user: ${email}`);
        await invalidateUserSessions(userId, 'User removed from security group');
      }
    }
  } catch (error) {
    console.error('Error polling audit logs:', error);
  }
}

// Get list of users recently removed from the security group
async function getRecentGroupRemovals(securityGroupId) {
  const token = await getGraphAccessToken();
  if (!token) return [];

  // Check last 2 minutes of audit logs (more frequent polling)
  const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();

  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName%20eq%20'Remove%20member%20from%20group'%20and%20activityDateTime%20ge%20${encodeURIComponent(twoMinutesAgo)}&$top=50`,
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
          if (res.statusCode === 200) {
            const response = JSON.parse(data);
            const audits = response.value || [];

            const removedUsers = [];

            for (const audit of audits) {
              const targetResources = audit.targetResources || [];

              // Check if this audit is about our target group
              const isTargetGroup = targetResources.some(tr =>
                tr.id === securityGroupId && tr.type === 'Group'
              );

              if (isTargetGroup) {
                // Find the user that was removed
                const removedUser = targetResources.find(tr =>
                  tr.type === 'User' && tr.userPrincipalName
                );

                if (removedUser) {
                  removedUsers.push(removedUser.userPrincipalName);
                  console.log(`Audit log: User ${removedUser.userPrincipalName} removed from group ${securityGroupId}`);
                }
              }
            }

            resolve(removedUsers);
          } else {
            console.error(`Audit log API error: ${res.statusCode}`, data);
            resolve([]);
          }
        } catch (e) {
          console.error('Error parsing audit logs:', e);
          resolve([]);
        }
      });
    });

    req.on('error', (err) => {
      console.error('Audit log request error:', err);
      resolve([]);
    });
    req.end();
  });
}

// Start polling (every 2 minutes for status, every 30 seconds for audit logs)
function startUserStatusPolling() {
  if (!GRAPH_CLIENT_ID || !GRAPH_CLIENT_SECRET || !GRAPH_TENANT_ID) {
    console.log('Graph API not configured. Set GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, GRAPH_TENANT_ID env vars');
    return;
  }

  console.log('Starting Entra user status polling (every 2 minutes)');
  console.log('Starting audit log polling for group removals (every 30 seconds)');

  // Run immediately on start
  pollUserStatus();

  // Then every 2 minutes for user status
  setInterval(pollUserStatus, 2 * 60 * 1000);

  // Poll audit logs every 30 seconds for faster group removal detection
  if (process.env.SAML_SECURITY_GROUP_ID) {
    setInterval(pollAuditLogsForGroupRemovals, 30 * 1000);
  }
}

module.exports = {
  startUserStatusPolling,
  checkUserStatusInEntra,
  checkUserGroupMembership,
  checkUserAppAccess,
  checkAuditLogsForGroupRemoval,
  getRecentGroupRemovals,
  pollUserStatus,
  invalidateUserSessions,
  // Multi-tenant exports
  getTenantGraphToken,
  getGraphTokenForConfig,
  tenantTokenCache
};
