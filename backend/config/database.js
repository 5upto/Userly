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