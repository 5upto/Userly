const express = require('express');
const { pool } = require('../config/database');
const { authenticateToken, requireAdmin, requireSuperAdmin } = require('../middleware/auth');
const { revokeUserSessions } = require('./saml');

const router = express.Router();

router.get('/', authenticateToken, async (req, res) => {
  try {
    const { rows: users } = await pool.query(`
      SELECT 
        id, 
        name, 
        email, 
        status,
        role,
        registration_time, 
        last_login_time,
        COALESCE(last_login_time, registration_time) as activity_time
      FROM users 
      ORDER BY activity_time DESC
    `);

    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.patch('/block', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs are required' });
    }

    // Get user details before blocking for session revocation
    const { rows: usersToBlock } = await pool.query(
      'SELECT id, email FROM users WHERE id = ANY($1::int[])',
      [userIds]
    );

    await pool.query(
      `UPDATE users SET status = 'blocked' WHERE id = ANY($1::int[])`,
      [userIds]
    );

    // Revoke all active sessions for blocked users (instant logout)
    for (const user of usersToBlock) {
      await revokeUserSessions(user.id, user.email, 'blocked');
    }

    res.json({ 
      message: 'Users blocked successfully',
      sessionsRevoked: usersToBlock.length 
    });
  } catch (error) {
    console.error('Error blocking users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.patch('/unblock', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs are required' });
    }

    await pool.query(
      `UPDATE users SET status = 'active' WHERE id = ANY($1::int[])`,
      [userIds]
    );

    res.json({ message: 'Users unblocked successfully' });
  } catch (error) {
    console.error('Error unblocking users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.delete('/', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs are required' });
    }

    // Prevent deleting yourself
    if (userIds.includes(req.user.id)) {
      return res.status(400).json({ message: 'Cannot delete yourself' });
    }

    await pool.query(
      `DELETE FROM users WHERE id = ANY($1::int[])`,
      [userIds]
    );

    res.json({ message: 'Users deleted successfully' });
  } catch (error) {
    console.error('Error deleting users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user role (Super Admin only)
router.patch('/:id/role', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role || !['standard', 'user', 'admin', 'super_admin'].includes(role)) {
      return res.status(400).json({ message: 'Valid role is required (standard, user, admin, super_admin)' });
    }

    // Prevent changing your own role
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ message: 'Cannot change your own role' });
    }

    const { rows } = await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, name, email, role',
      [role, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User role updated successfully', user: rows[0] });
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;