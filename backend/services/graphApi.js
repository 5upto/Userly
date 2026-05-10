const https = require('https');
const { blacklistToken } = require('./tokenBlacklist');
const { pool } = require('../config/database');

// Microsoft Graph API configuration (legacy single-tenant support)
const GRAPH_CLIENT_ID = process.env.GRAPH_CLIENT_ID;
const GRAPH_CLIENT_SECRET = process.env.GRAPH_CLIENT_SECRET;
const GRAPH_TENANT_ID = process.env.GRAPH_TENANT_ID;

let accessToken = null;
let tokenExpiry = 0;

// Multi-tenant token cache: tenantId -> { token, expiry }
const tenantTokenCache = new Map();

// In-memory cache for blocked users: email -> { timestamp }
const blockedUsersCache = new Map();
const BLOCKED_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

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
async function checkUserStatusInEntra(email, token) {
  if (!token) {
    token = await getGraphAccessToken();
  }
  if (!token) return null;

  // First, find the user by email (handles external/guest users with #EXT# UPNs)
  const userId = await getUserIdByEmail(email, token);

  if (!userId) {
    console.log(`User ${email} not found in this Entra tenant (external user or wrong tenant)`);
    return { exists: false, blocked: false, wrongTenant: true };
  }

  // Now get the user's account status using their ID
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${encodeURIComponent(userId)}?$select=accountEnabled`,
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
            const user = JSON.parse(data);
            resolve({
              exists: true,
              blocked: !user.accountEnabled
            });
          } else if (res.statusCode === 404) {
            resolve({ exists: false, blocked: false, wrongTenant: true });
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
async function checkUserGroupMembership(email, securityGroupId, token) {
  if (!token) {
    token = await getGraphAccessToken();
  }
  if (!token) return null;

  // First get user ID
  const userId = await getUserIdByEmail(email, token);
  if (!userId) return { isMember: false, reason: 'User not found' };

  // Use the transitiveMembers endpoint to check membership directly
  // This is more efficient and handles large groups correctly
  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/groups/${encodeURIComponent(securityGroupId)}/members/${encodeURIComponent(userId)}/$ref`,
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
          if (res.statusCode === 204) {
            // 204 No Content means user IS a member
            resolve({ isMember: true, reason: null });
          } else if (res.statusCode === 404) {
            // 404 Not Found means user is NOT a member
            resolve({ isMember: false, reason: 'User not in security group' });
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
async function checkUserAppAccess(email, securityGroupId, token) {
  if (!token) {
    token = await getGraphAccessToken();
  }
  if (!token) return null;

  // Check if user is member of the security group
  const membership = await checkUserGroupMembership(email, securityGroupId, token);

  if (!membership || !membership.isMember) {
    return { hasAccess: false, reason: membership?.reason || 'User not in security group' };
  }

  return { hasAccess: true };
}

async function getUserIdByEmail(email, accessToken) {
  // Try multiple search methods to find external/guest users
  // Method 1: Search by mail attribute (original email)
  // Method 2: Search by otherMails (alternate emails)
  // Method 3: Try direct UPN (for internal users)

  return new Promise((resolve) => {
    // Use $filter to search by mail or otherMails - this works for external users
    // whose UPN is transformed (e.g., user_domain.com#EXT#@tenant.onmicrosoft.com)
    const filter = `mail eq '${email}' or otherMails/any(x:x eq '${email}')`;
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users?$filter=${encodeURIComponent(filter)}&$select=id,userPrincipalName,mail`,
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
            if (response.value && response.value.length > 0) {
              const user = response.value[0];
              console.log(`Found user ${email} in Entra: ${user.id} (UPN: ${user.userPrincipalName})`);
              resolve(user.id);
            } else {
              // No user found with mail/otherMails filter, try direct UPN lookup as fallback
              tryDirectUpnLookup();
            }
          } else {
            tryDirectUpnLookup();
          }
        } catch (e) {
          tryDirectUpnLookup();
        }
      });
    });

    req.on('error', () => tryDirectUpnLookup());
    req.end();

    // Fallback: try direct UPN lookup (for internal users)
    function tryDirectUpnLookup() {
      const directOptions = {
        hostname: 'graph.microsoft.com',
        path: `/v1.0/users/${encodeURIComponent(email)}?$select=id`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      };

      const directReq = https.request(directOptions, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode === 200) {
              const user = JSON.parse(data);
              console.log(`Found user ${email} via direct UPN: ${user.id}`);
              resolve(user.id);
            } else {
              console.log(`User ${email} not found in Entra tenant`);
              resolve(null);
            }
          } catch (e) {
            resolve(null);
          }
        });
      });

      directReq.on('error', () => resolve(null));
      directReq.end();
    }
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

// Get Graph token for user based on their email domain's SAML config
async function getGraphTokenForUser(email) {
  try {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return null;

    // Find SAML config that matches this user's domain
    const { rows: configs } = await pool.query(
      `SELECT tenant_id, client_id, client_secret, graph_api_enabled, security_group_id
       FROM saml_configs
       WHERE graph_api_enabled = true
       AND tenant_id IS NOT NULL
       AND client_id IS NOT NULL
       AND client_secret IS NOT NULL
       AND (allowed_domains ILIKE $1 OR allowed_domains ILIKE $2)`,
      [`%${domain}%`, `%${email.toLowerCase()}%`]
    );

    if (configs.length === 0) {
      console.log(`No SAML config with Graph API found for domain: ${domain}`);
      return { token: await getGraphAccessToken(), config: null }; // Fall back to global
    }

    const config = configs[0];
    const token = await getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
    return { token, config };
  } catch (error) {
    console.error('Error getting Graph token for user:', error);
    return { token: await getGraphAccessToken(), config: null };
  }
}

// Cache for user-tenant mappings to avoid repeated searches: email -> { tenantId, timestamp }
const userTenantCache = new Map();
const USER_TENANT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Find user across all configured SAML tenants
async function findUserAndGetToken(email) {
  try {
    // Check cache first
    const cached = userTenantCache.get(email.toLowerCase());
    if (cached && (Date.now() - cached.timestamp) < USER_TENANT_CACHE_TTL) {
      // Use cached tenant
      const { rows: configs } = await pool.query(
        `SELECT id, tenant_id, client_id, client_secret, graph_api_enabled, security_group_id, saml_name
         FROM saml_configs
         WHERE tenant_id = $1 AND graph_api_enabled = true`,
        [cached.tenantId]
      );

      if (configs.length > 0) {
        const config = configs[0];
        const token = await getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
        if (token) {
          // Verify user still exists in this tenant
          const userId = await getUserIdByEmail(email, token);
          if (userId) {
            return { token, config, userId };
          }
        }
      }
      // Cache miss or user moved, clear cache and search again
      userTenantCache.delete(email.toLowerCase());
    }

    // Get all SAML configs with Graph API enabled
    const { rows: configs } = await pool.query(
      `SELECT id, tenant_id, client_id, client_secret, graph_api_enabled, security_group_id, saml_name
       FROM saml_configs
       WHERE graph_api_enabled = true
       AND tenant_id IS NOT NULL
       AND client_id IS NOT NULL
       AND client_secret IS NOT NULL`
    );

    if (configs.length === 0) {
      console.log(`No SAML configs with Graph API enabled`);
      return null;
    }

    // Single config optimization: use it directly
    if (configs.length === 1) {
      const config = configs[0];
      try {
        const token = await getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
        if (!token) {
          console.log(`Failed to get token for single config ${config.saml_name}`);
          return null;
        }

        const userId = await getUserIdByEmail(email, token);
        if (userId) {
          console.log(`Found user ${email} in single tenant ${config.tenant_id} (${config.saml_name})`);
          // Cache the result
          userTenantCache.set(email.toLowerCase(), { tenantId: config.tenant_id, timestamp: Date.now() });
          return { token, config, userId };
        }
        console.log(`User ${email} not found in single configured tenant ${config.tenant_id}`);
        return null;
      } catch (err) {
        console.error(`Error checking single config:`, err.message);
        return null;
      }
    }

    // Multiple configs: try each to find the user
    for (const config of configs) {
      try {
        const token = await getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
        if (!token) continue;

        // Try to find user in this tenant
        const userId = await getUserIdByEmail(email, token);

        if (userId) {
          console.log(`Found user ${email} in tenant ${config.tenant_id} (${config.saml_name})`);
          // Cache the result
          userTenantCache.set(email.toLowerCase(), { tenantId: config.tenant_id, timestamp: Date.now() });
          return { token, config, userId };
        }
      } catch (err) {
        // Continue to next config
        continue;
      }
    }

    console.log(`User ${email} not found in any configured tenant`);
    return null;
  } catch (error) {
    console.error('Error finding user across tenants:', error);
    return null;
  }
}

// Poll all SAML users and invalidate sessions of blocked/revoked users
async function pollUserStatus() {
  try {
    // Get ALL SAML users (not just recent ones) to ensure continuous monitoring
    const { rows: samlUsers } = await pool.query(
      `SELECT DISTINCT u.id, u.email, u.status
       FROM users u
       JOIN user_sessions us ON u.id = us.user_id
       WHERE us.auth_type = 'saml'
       AND u.email IS NOT NULL`
    );

    if (samlUsers.length === 0) {
      console.log('No SAML users found to poll');
      return;
    }

    console.log(`Polling ${samlUsers.length} SAML users against Entra...`);

    for (const user of samlUsers) {
      // Find user across all configured tenants
      const tenantInfo = await findUserAndGetToken(user.email);

      if (!tenantInfo) {
        console.log(`User ${user.email} not found in any Entra tenant, skipping checks`);
        continue;
      }

      const { token, config } = tenantInfo;

      // Check 1: Is user blocked/disabled in Entra?
      const entraStatus = await checkUserStatusInEntra(user.email, token);

      if (entraStatus && entraStatus.blocked) {
        // Only block if not already blocked in database
        if (user.status !== 'blocked') {
          console.log(`User ${user.email} is BLOCKED in Entra (tenant: ${config.tenant_id}), invalidating session`);
          await invalidateUserSessions(user.id, 'User blocked in Entra ID');
        }
        continue;
      }

      // Check 2: Does user still have app access (security group membership)?
      if (config?.security_group_id) {
        const appAccess = await checkUserAppAccess(user.email, config.security_group_id, token);

        if (appAccess && !appAccess.hasAccess) {
          // Only block if not already blocked in database
          if (user.status !== 'blocked') {
            console.log(`User ${user.email} removed from security group in tenant ${config.tenant_id}, invalidating session`);
            await invalidateUserSessions(user.id, appAccess.reason || 'User removed from security group');
          }
          continue;
        }
      }

      console.log(`User ${user.email} check passed in tenant ${config.tenant_id}`);
    }

    // Also check blocked users to see if they should be unblocked
    const { rows: blockedUsers } = await pool.query(
      `SELECT id, email, status FROM users WHERE status = 'blocked' AND email IS NOT NULL`
    );

    if (blockedUsers.length > 0) {
      console.log(`Checking ${blockedUsers.length} blocked users for potential unblock...`);

      for (const user of blockedUsers) {
        const tenantInfo = await findUserAndGetToken(user.email);

        if (!tenantInfo) {
          continue;
        }

        const { token, config } = tenantInfo;

        // Check if user is now enabled in Entra
        const entraStatus = await checkUserStatusInEntra(user.email, token);

        if (entraStatus && !entraStatus.blocked) {
          console.log(`User ${user.email} is now ENABLED in Entra (tenant: ${config.tenant_id}), unblocking`);
          await unblockUser(user.id, 'User unblocked in Entra ID');
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

    // Blacklist all tokens with the reason
    for (const session of sessions) {
      blacklistToken(session.token, reason);
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

    // Add to cache for fast lookups
    const { rows: user } = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (user.length > 0 && user[0].email) {
      blockedUsersCache.set(user[0].email.toLowerCase(), { timestamp: Date.now() });
    }

    console.log(`Invalidated ${sessions.length} sessions for user ${userId}: ${reason}`);
  } catch (error) {
    console.error('Error invalidating user sessions:', error);
  }
}

// Unblock user in database and restore their status
async function unblockUser(userId, reason) {
  try {
    // Update local user status to active
    await pool.query(
      `UPDATE users SET status = 'active' WHERE id = $1`,
      [userId]
    );

    // Remove from cache
    const { rows: user } = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (user.length > 0 && user[0].email) {
      blockedUsersCache.delete(user[0].email.toLowerCase());
    }

    console.log(`Unblocked user ${userId}: ${reason}`);
    return true;
  } catch (error) {
    console.error('Error unblocking user:', error);
    return false;
  }
}

// Check if user is blocked using in-memory cache (fast lookup)
function isUserBlockedInCache(email) {
  if (!email) return false;
  const cached = blockedUsersCache.get(email.toLowerCase());
  if (!cached) return false;
  
  // Check if cache entry is still valid
  if (Date.now() - cached.timestamp > BLOCKED_CACHE_TTL) {
    blockedUsersCache.delete(email.toLowerCase());
    return false;
  }
  
  return true;
}

// Check if user is blocked (uses cache first, falls back to DB)
async function isUserBlocked(email) {
  if (!email) return false;
  
  // Check cache first for fast lookup
  if (isUserBlockedInCache(email)) {
    return true;
  }
  
  // Fall back to database check
  try {
    const { rows: users } = await pool.query(
      'SELECT status FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    
    if (users.length > 0 && users[0].status === 'blocked') {
      // Add to cache for future lookups
      blockedUsersCache.set(email.toLowerCase(), { timestamp: Date.now() });
      return true;
    }
    
    return false;
  } catch (error) {
    console.error('Error checking user blocked status:', error);
    return false;
  }
}

// Poll for group removals via audit logs (more frequent)
async function pollAuditLogsForGroupRemovals() {
  try {
    // Get all SAML configs with security groups
    const { rows: configs } = await pool.query(
      `SELECT tenant_id, client_id, client_secret, security_group_id, saml_name
       FROM saml_configs
       WHERE graph_api_enabled = true
       AND security_group_id IS NOT NULL
       AND tenant_id IS NOT NULL
       AND client_id IS NOT NULL
       AND client_secret IS NOT NULL`
    );

    if (configs.length === 0) {
      return;
    }

    // Check each tenant's audit logs for group removals
    for (const config of configs) {
      try {
        const token = await getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
        if (!token) continue;

        // Check audit logs for recent group removals
        const removedUsers = await getRecentGroupRemovals(config.security_group_id, token);

        if (removedUsers.length === 0) continue;

        console.log(`Found ${removedUsers.length} users removed from security group in tenant ${config.tenant_id} (${config.saml_name})`);

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
      } catch (err) {
        console.error(`Error checking audit logs for tenant ${config.tenant_id}:`, err.message);
        continue;
      }
    }
  } catch (error) {
    console.error('Error polling audit logs:', error);
  }
}

// Poll for group additions via audit logs (to unblock users)
async function pollAuditLogsForGroupAdditions() {
  try {
    // Get all SAML configs with security groups
    const { rows: configs } = await pool.query(
      `SELECT tenant_id, client_id, client_secret, security_group_id, saml_name
       FROM saml_configs
       WHERE graph_api_enabled = true
       AND security_group_id IS NOT NULL
       AND tenant_id IS NOT NULL
       AND client_id IS NOT NULL
       AND client_secret IS NOT NULL`
    );

    if (configs.length === 0) {
      return;
    }

    // Check each tenant's audit logs for group additions
    for (const config of configs) {
      try {
        const token = await getTenantGraphToken(config.tenant_id, config.client_id, config.client_secret);
        if (!token) continue;

        // Check audit logs for recent group additions
        const addedUsers = await getRecentGroupAdditions(config.security_group_id, token);

        if (addedUsers.length === 0) continue;

        console.log(`Found ${addedUsers.length} users added to security group in tenant ${config.tenant_id} (${config.saml_name})`);

        // For each added user, check if they were blocked and unblock them
        for (const email of addedUsers) {
          // Find user in database
          const { rows: users } = await pool.query(
            'SELECT id, status FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
          );

          if (users.length > 0) {
            const user = users[0];
            if (user.status === 'blocked') {
              console.log(`Unblocking user added back to security group: ${email}`);
              await unblockUser(user.id, 'User added back to security group');
            }
          }
        }
      } catch (err) {
        console.error(`Error checking audit logs for group additions in tenant ${config.tenant_id}:`, err.message);
        continue;
      }
    }
  } catch (error) {
    console.error('Error polling audit logs for group additions:', error);
  }
}

// Get list of users recently removed from the security group
async function getRecentGroupRemovals(securityGroupId, token) {
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
              // Check if this audit is for our security group
              if (audit.targetResources && audit.targetResources.length > 0) {
                const groupResource = audit.targetResources.find(r => r.type === 'Group');
                if (groupResource && groupResource.id === securityGroupId) {
                  // Extract the user who was removed
                  const userResource = audit.targetResources.find(r => r.type === 'User');
                  if (userResource && userResource.userPrincipalName) {
                    removedUsers.push(userResource.userPrincipalName);
                    console.log(`Audit log: User ${userResource.userPrincipalName} removed from group ${securityGroupId}`);
                  }
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

// Get list of users recently added to the security group
async function getRecentGroupAdditions(securityGroupId, token) {
  if (!token) return [];

  // Check last 2 minutes of audit logs (more frequent polling)
  const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();

  return new Promise((resolve) => {
    const options = {
      hostname: 'graph.microsoft.com',
      path: `/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName%20eq%20'Add%20member%20to%20group'%20and%20activityDateTime%20ge%20${encodeURIComponent(twoMinutesAgo)}&$top=50`,
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

            const addedUsers = [];
            for (const audit of audits) {
              // Check if this audit is for our security group
              if (audit.targetResources && audit.targetResources.length > 0) {
                const groupResource = audit.targetResources.find(r => r.type === 'Group');
                if (groupResource && groupResource.id === securityGroupId) {
                  // Extract the user who was added
                  const userResource = audit.targetResources.find(r => r.type === 'User');
                  if (userResource && userResource.userPrincipalName) {
                    addedUsers.push(userResource.userPrincipalName);
                    console.log(`Audit log: User ${userResource.userPrincipalName} added to group ${securityGroupId}`);
                  }
                }
              }
            }

            resolve(addedUsers);
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

// Check if any Graph API credentials are available (global or SAML configs)
async function isGraphApiConfigured() {
  // Check for global credentials
  if (GRAPH_CLIENT_ID && GRAPH_CLIENT_SECRET && GRAPH_TENANT_ID) {
    return true;
  }

  // Check for SAML config credentials
  try {
    const { rows: configs } = await pool.query(
      `SELECT id FROM saml_configs
       WHERE graph_api_enabled = true
       AND tenant_id IS NOT NULL
       AND client_id IS NOT NULL
       AND client_secret IS NOT NULL
       LIMIT 1`
    );
    return configs.length > 0;
  } catch (e) {
    return false;
  }
}

// Start polling (every 10 seconds for faster detection)
async function startUserStatusPolling() {
  const hasGraphConfig = await isGraphApiConfigured();

  if (!hasGraphConfig) {
    console.log('Graph API not configured. Set GRAPH_CLIENT_ID/SECRET/TENANT_ID env vars OR configure SAML with Graph API credentials');
    return;
  }

  console.log('Starting Entra user status polling (every 10 seconds)');
  console.log('Starting audit log polling for group removals (every 10 seconds)');
  console.log('Starting audit log polling for group additions (every 10 seconds)');

  // Run immediately on start
  pollUserStatus();

  // Poll every 10 seconds for faster detection
  setInterval(pollUserStatus, 10 * 1000);

  // Poll audit logs every 10 seconds for faster group removal detection
  setInterval(pollAuditLogsForGroupRemovals, 10 * 1000);

  // Poll audit logs every 10 seconds for faster group addition detection
  setInterval(pollAuditLogsForGroupAdditions, 10 * 1000);
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
  unblockUser,
  pollAuditLogsForGroupAdditions,
  getRecentGroupAdditions,
  isUserBlocked,
  isUserBlockedInCache,
  blockedUsersCache,
  // Multi-tenant exports
  getTenantGraphToken,
  getGraphTokenForConfig,
  getGraphTokenForUser,
  findUserAndGetToken,
  tenantTokenCache
};
