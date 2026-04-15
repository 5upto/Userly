const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');

const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const { rows: existingUsers } = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3)',
      [name, email, hashedPassword]
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const { rows: users } = await pool.query(
      'SELECT id, name, email, password, status, role FROM users WHERE email = $1',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];

    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'Account is blocked' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    await pool.query(
      'UPDATE users SET last_login_time = NOW() WHERE id = $1',
      [user.id]
    );

    const token = jwt.sign(
      { userId: user.id, email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        status: user.status,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Token refresh endpoint for SAML users
// Allows silent token renewal while checking if user still exists/is active
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token required' });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET || 'fallback-secret-key');

    if (decoded.authType !== 'saml_refresh') {
      return res.status(401).json({ message: 'Invalid refresh token type' });
    }

    // Check session age - force re-auth with Entra after 30 minutes
    // This ensures if user is blocked/revoked in Entra, app detects within 30 min max
    const SESSION_MAX_AGE = 30 * 60 * 1000; // 30 minutes in milliseconds
    const authTime = decoded.authTime || decoded.iat * 1000;
    const now = Date.now();

    if (now - authTime > SESSION_MAX_AGE) {
      console.log('SAML session exceeded max age (30min), forcing re-authentication');
      return res.status(401).json({
        message: 'Session expired, please re-authenticate',
        redirect: true,
        forceReauth: true
      });
    }

    // Check if user still exists and is active
    const { rows: users } = await pool.query(
      'SELECT id, name, email, status, role FROM users WHERE email = $1',
      [decoded.email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'User not found', redirect: true });
    }

    const user = users[0];

    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'Account is blocked', redirect: true });
    }

    // Generate new short-lived access token
    const newToken = jwt.sign(
      { userId: user.id, email: user.email, name: user.name, role: user.role || 'standard', authType: 'saml' },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '15m' }
    );

    res.json({
      token: newToken,
      expiresIn: 900, // 15 minutes in seconds
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        status: user.status,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Refresh token expired', redirect: true });
    }
    res.status(401).json({ message: 'Invalid refresh token', redirect: true });
  }
});

module.exports = router;