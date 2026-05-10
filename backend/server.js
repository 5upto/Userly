const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
require('dotenv').config();

const { initDatabase } = require('./config/database');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const samlRoutes = require('./routes/saml');
const oidcRoutes = require('./routes/oidc');
const { startUserStatusPolling } = require('./services/graphApi');

const app = express();
const PORT = process.env.PORT || 3000;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  skip: (req) => req.path.startsWith('/api/auth')
});

app.use(limiter);

// Allow CORS for SAML routes (IdP posts from its own domain) - must be before global CORS
app.use('/api/saml', cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Allow CORS for OIDC routes
app.use('/api/oidc', cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(cors({ 
  origin: ['https://userly-pro.vercel.app', 'http://localhost:5173'],
  credentials: true 
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// Allow SAML ACS endpoint to be loaded from frames and accept CORS from any origin (required for SAML POST binding from IdP)
app.use((req, res, next) => {
  if (req.path === '/api/saml/acs') {
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self' *");
    res.removeHeader('X-Frame-Options');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'false');
  }
  next();
});

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/saml', samlRoutes);
app.use('/api/oidc', oidcRoutes);

app.get('/api/health', (req, res) => {
  res.json({ message: 'Server is running', timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  console.error('Global error handler:', err.stack);

  // Check for Graph API errors related to disabled/blocked users
  const errorMsg = err.message || err.toString() || JSON.stringify(err) || '';
  if (errorMsg.includes('disabled') || errorMsg.includes('Unauthorized') || errorMsg.includes('Authorization_IdentityDisabled') || errorMsg.includes('401')) {
    console.log('Graph API error in global handler, redirecting to blocked page');
    return res.redirect('https://userly-pro.vercel.app/login?blocked=true&reason=entra_blocked');
  }

  res.status(500).json({ message: 'Something went wrong!' });
});

const startServer = async () => {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Health check available at http://localhost:${PORT}/api/health`);
    });

    // Start Microsoft Graph API polling for Entra user status (outside listener callback)
    await startUserStatusPolling();
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();