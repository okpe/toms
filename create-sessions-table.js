const db = require('./database'); // Uses your existing database module

async function run() {
  try {
    console.log('Connecting to Turso...');
    
    // Execute using your existing runAsync helper
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid VARCHAR PRIMARY KEY,
        sess TEXT NOT NULL,
        expired DATETIME NOT NULL
      );
    `);

    console.log('✅ Success! "sessions" table created in Turso.');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error creating sessions table:', err);
    process.exit(1);
  }
}

run();