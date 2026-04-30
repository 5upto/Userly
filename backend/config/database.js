const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
});

const initDatabase = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        status TEXT CHECK (status IN ('active','blocked')) DEFAULT 'active',
        role TEXT CHECK (role IN ('user','admin','super_admin')) DEFAULT 'user',
        registration_time TIMESTAMPTZ DEFAULT NOW(),
        last_login_time TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)
    `);

    // Create SAML configs table
    await client.query(`
      CREATE TABLE IF NOT EXISTS saml_configs (
        id BIGINT PRIMARY KEY,
        saml_name VARCHAR(255) NOT NULL,
        allowed_domains TEXT,
        issuer_url TEXT,
        idp_sso_url TEXT NOT NULL,
        idp_certificate TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Migration: Add role column if it doesn't exist (for existing tables)
    await client.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS role TEXT CHECK (role IN ('user','admin','super_admin')) DEFAULT 'user'
    `);

    // Migration: Add idp_slo_url column for Single Logout support
    await client.query(`
      ALTER TABLE saml_configs 
      ADD COLUMN IF NOT EXISTS idp_slo_url TEXT
    `);

    // Migration: Add multi-tenant SSO columns - enabled toggle and Graph API credentials
    await client.query(`
      ALTER TABLE saml_configs 
      ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true
    `);
    await client.query(`
      ALTER TABLE saml_configs 
      ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255)
    `);
    await client.query(`
      ALTER TABLE saml_configs 
      ADD COLUMN IF NOT EXISTS client_id VARCHAR(255)
    `);
    await client.query(`
      ALTER TABLE saml_configs 
      ADD COLUMN IF NOT EXISTS client_secret TEXT
    `);
    await client.query(`
      ALTER TABLE saml_configs 
      ADD COLUMN IF NOT EXISTS graph_api_enabled BOOLEAN DEFAULT false
    `);

    // Create user_sessions table for tracking active SAML sessions (for Graph API polling)
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        auth_type TEXT DEFAULT 'saml',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        invalidated_at TIMESTAMPTZ NULL,
        invalidated_reason TEXT NULL
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token)
    `);

    // Migration: Add invalidated_reason column if not exists
    await client.query(`
      ALTER TABLE user_sessions
      ADD COLUMN IF NOT EXISTS invalidated_reason TEXT NULL
    `);

    // Migration: Add unique constraint on token column for ON CONFLICT
    try {
      await client.query(`
        ALTER TABLE user_sessions
        ADD CONSTRAINT user_sessions_token_unique UNIQUE (token)
      `);
      console.log('Added unique constraint on user_sessions.token');
    } catch (constraintError) {
      // Constraint already exists or table doesn't exist yet, ignore
      if (constraintError.code === '42P07' || constraintError.message?.includes('already exists')) {
        console.log('Unique constraint on token already exists');
      } else {
        console.log('Note: Could not add unique constraint (may already exist):', constraintError.message);
      }
    }

    // Set supto.shawon2002@gmail.com as Super Admin
    await client.query(`
      UPDATE users 
      SET role = 'super_admin' 
      WHERE email = 'supto.shawon2002@gmail.com'
    `);

    console.log('Tables created successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
  } finally {
    client.release();
  }
};

module.exports = { pool, initDatabase };