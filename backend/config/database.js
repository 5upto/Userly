const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const initDatabase = async () => {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD
    });

    // await connection.execute(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME}`);
    // console.log('Database created or already exists');

    await connection.end();

    await createTables();
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
  }
};

const createTables = async () => {
  try {
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        status ENUM('active', 'blocked') DEFAULT 'active',
        registration_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login_time TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Check if the index already exists
    const [rows] = await pool.execute(`
      SELECT COUNT(1) as count FROM information_schema.statistics
      WHERE table_schema = DATABASE() AND table_name = 'users' AND index_name = 'idx_users_email';
    `);

    if (rows[0].count === 0) {
      await pool.execute(`
        CREATE UNIQUE INDEX idx_users_email ON users(email)
      `);
      console.log('Unique index created on users(email)');
    } else {
      console.log('Unique index on users(email) already exists');
    }

    console.log('Tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
    throw error;
  }
};

module.exports = { pool, initDatabase };