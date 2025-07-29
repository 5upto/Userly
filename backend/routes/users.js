const express = require('express');
const { pool } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

router.get('/', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(`
      SELECT 
        id, 
        name, 
        email, 
        status, 
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

router.patch('/block', authenticateToken, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs are required' });
    }

    const placeholders = userIds.map(() => '?').join(',');
    await pool.execute(
      `UPDATE users SET status = 'blocked' WHERE id IN (${placeholders})`,
      userIds
    );

    res.json({ message: 'Users blocked successfully' });
  } catch (error) {
    console.error('Error blocking users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.patch('/unblock', authenticateToken, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs are required' });
    }

    const placeholders = userIds.map(() => '?').join(',');
    await pool.execute(
      `UPDATE users SET status = 'active' WHERE id IN (${placeholders})`,
      userIds
    );

    res.json({ message: 'Users unblocked successfully' });
  } catch (error) {
    console.error('Error unblocking users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.delete('/', authenticateToken, async (req, res) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs are required' });
    }

    const placeholders = userIds.map(() => '?').join(',');
    await pool.execute(
      `DELETE FROM users WHERE id IN (${placeholders})`,
      userIds
    );

    res.json({ message: 'Users deleted successfully' });
  } catch (error) {
    console.error('Error deleting users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;