require('dotenv').config();
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');

// Initialize Turso Client (Uses cloud Turso DB in production, local file in development)
const client = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:helpdesk.db',
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

/* ==========================================================================
   PROMISE-BASED HELPER WRAPPERS FOR TURSO (@libsql/client)
   ========================================================================== */

const db = {
  // Executes SELECT queries expecting a single row
  async getAsync(sql, params = []) {
    const res = await client.execute({ sql, args: params });
    return res.rows.length > 0 ? res.rows[0] : null;
  },

  // Executes INSERT, UPDATE, DELETE queries
  async runAsync(sql, params = []) {
    const res = await client.execute({ sql, args: params });
    return {
      id: res.lastInsertRowid !== undefined ? Number(res.lastInsertRowid) : null,
      changes: res.rowsAffected
    };
  },

  // Executes SELECT queries returning an array of row objects
  async allAsync(sql, params = []) {
    const res = await client.execute({ sql, args: params });
    return res.rows;
  },

  // Dummy close method for backwards compatibility
  async closeAsync() {
    return Promise.resolve();
  }
};

/* ==========================================================================
   SCHEMA INITIALIZATION & SEEDING
   ========================================================================== */

async function initSchema() {
  try {
    // 1. Users table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT CHECK(role IN ('requester', 'manager', 'admin', 'super_admin')) DEFAULT 'requester',
        manager_id INTEGER,
        subsidiary TEXT,
        department TEXT,
        access_helpdesk INTEGER DEFAULT 1,
        access_assets INTEGER DEFAULT 1,
        must_change_password INTEGER DEFAULT 1,
        reset_token_hash TEXT,
        reset_token_expires DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // 2. System state table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS system_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);

    await db.runAsync(`INSERT OR IGNORE INTO system_state (key, value) VALUES ('accepting_tickets', 'true')`);

    // 3. Tickets table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_number TEXT UNIQUE,
        ticket_type TEXT CHECK(ticket_type IN ('Incident', 'Service Request', 'Change Request')) DEFAULT 'Incident',
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        priority TEXT CHECK(priority IN ('Critical', 'High', 'Medium', 'Low')) DEFAULT 'Medium',
        status TEXT CHECK(status IN (
          'Open', 'Approved', 'Rejected', 'In Progress', 'Pending Customer', 'Resolved', 'Closed'
        )) DEFAULT 'Open',
        requester_id INTEGER NOT NULL,
        manager_id INTEGER,
        assigned_to INTEGER,
        subsidiary TEXT,
        department TEXT,
        asset_id INTEGER,
        quantity INTEGER DEFAULT 1,
        cost REAL DEFAULT 0,
        po_number TEXT,
        vendor TEXT,
        location TEXT,
        rejection_reason TEXT,
        resolution_notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME,
        closed_at DATETIME,
        sla_target_resolution DATETIME,
        sla_resolution_status TEXT DEFAULT 'Pending',
        FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (asset_id) REFERENCES assets(id)
      )
    `);

    // 4. Ticket history table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS ticket_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // 5. Assets table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_tag TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        model TEXT NOT NULL,
        serial_number TEXT UNIQUE,
        status TEXT CHECK(status IN ('In Stock', 'Assigned', 'Under Repair', 'Retired', 'Refreshed')) DEFAULT 'In Stock',
        assigned_to INTEGER,
        cost REAL DEFAULT 0,
        salvage_value REAL DEFAULT 0,
        po_number TEXT,
        vendor TEXT,
        location TEXT,
        purchase_date DATE,
        warranty_expiry DATE,
        last_repair_date DATE,
        refreshed_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // 6. Asset repair logs table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS asset_repair_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        repair_start_date DATE NOT NULL,
        repair_end_date DATE,
        issue_description TEXT NOT NULL,
        repair_cost REAL DEFAULT 0,
        repaired_by TEXT,
        status TEXT CHECK(status IN ('In Progress', 'Completed', 'Unrepairable')) DEFAULT 'In Progress',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
      )
    `);

    // 7. User security questions table
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS user_security_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        question_1 TEXT NOT NULL,
        answer_1_hash TEXT NOT NULL,
        question_2 TEXT NOT NULL,
        answer_2_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Performance Indexes
    await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)`);
    await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tickets_requester ON tickets(requester_id)`);
    await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tickets_assigned ON tickets(assigned_to)`);
    await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status)`);
    await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_assets_assigned ON assets(assigned_to)`);
    await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_security_questions_user ON user_security_questions(user_id)`);

    // Safe Column Migrations
    const safeAddColumn = async (table, column, typeDef) => {
      try {
        await db.runAsync(`ALTER TABLE ${table} ADD COLUMN ${column} ${typeDef}`);
      } catch (err) {
        if (!/duplicate column/i.test(err.message)) {
          console.error(`[!] Error adding ${column} to ${table}:`, err.message);
        }
      }
    };

    await safeAddColumn('users', 'access_helpdesk', 'INTEGER DEFAULT 1');
    await safeAddColumn('users', 'access_assets', 'INTEGER DEFAULT 1');
    await safeAddColumn('users', 'must_change_password', 'INTEGER DEFAULT 1');
    await safeAddColumn('users', 'subsidiary', 'TEXT');
    await safeAddColumn('users', 'department', 'TEXT');

    await safeAddColumn('tickets', 'subsidiary', 'TEXT');
    await safeAddColumn('tickets', 'department', 'TEXT');
    await safeAddColumn('tickets', 'asset_id', 'INTEGER REFERENCES assets(id)');
    await safeAddColumn('tickets', 'quantity', 'INTEGER DEFAULT 1');
    await safeAddColumn('tickets', 'cost', 'REAL DEFAULT 0');
    await safeAddColumn('tickets', 'po_number', 'TEXT');
    await safeAddColumn('tickets', 'vendor', 'TEXT');
    await safeAddColumn('tickets', 'location', 'TEXT');

    await safeAddColumn('assets', 'cost', 'REAL DEFAULT 0');
    await safeAddColumn('assets', 'salvage_value', 'REAL DEFAULT 0');
    await safeAddColumn('assets', 'po_number', 'TEXT');
    await safeAddColumn('assets', 'vendor', 'TEXT');
    await safeAddColumn('assets', 'location', 'TEXT');
    await safeAddColumn('assets', 'last_repair_date', 'DATE');
    await safeAddColumn('assets', 'refreshed_at', 'DATETIME');

    await db.runAsync(`UPDATE users SET must_change_password = 1 WHERE must_change_password IS NULL AND role != 'super_admin'`);

    await migrateLegacyResolvers();
    await seedSuperAdminUser();
  } catch (err) {
    console.error('Schema initialization error:', err);
  }
}

async function migrateLegacyResolvers() {
  try {
    const res = await db.runAsync(`UPDATE users SET role = 'admin', access_helpdesk = 1 WHERE LOWER(role) = 'resolver'`);
    if (res.changes > 0) {
      console.log(`[+] Migrated ${res.changes} legacy resolver account(s) to admin.`);
    }
  } catch (err) {
    console.error('[-] Error migrating legacy resolver roles:', err.message);
  }
}

async function seedSuperAdminUser() {
  const defaultEmail = 'superadmin@helpdesk.local';
  const defaultPassword = 'SuperAdmin123!';
  const hashedPassword = bcrypt.hashSync(defaultPassword, 10);

  try {
    const row = await db.getAsync('SELECT id FROM users WHERE LOWER(email) = ?', [defaultEmail]);

    if (!row) {
      await db.runAsync(
        `INSERT INTO users (name, email, password, role, access_helpdesk, access_assets, must_change_password, subsidiary, department) VALUES (?, ?, ?, 'super_admin', 1, 1, 0, 'Arkland Group', 'IT')`,
        ['Super Admin', defaultEmail, hashedPassword]
      );
      console.log('[+] Super Admin seeded: superadmin@helpdesk.local / SuperAdmin123!');
    } else {
      await db.runAsync(
        `UPDATE users SET password = ?, role = 'super_admin', access_helpdesk = 1, access_assets = 1, must_change_password = 0 WHERE id = ?`,
        [hashedPassword, row.id]
      );
      console.log('[+] Super Admin account verified & credentials updated.');
    }
  } catch (err) {
    console.error('[-] Failed to seed/verify Super Admin:', err.message);
  }
}

initSchema();

/* ==========================================================================
   AUTH HELPER FUNCTIONS
   ========================================================================== */

db.findUserByEmail = async function (email) {
  return await db.getAsync('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email]);
};

db.updateUserResetToken = async function (userId, tokenHash, expiresAt) {
  return await db.runAsync(
    'UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?',
    [tokenHash, expiresAt.toISOString(), userId]
  );
};

db.findUserByResetToken = async function (tokenHash) {
  return await db.getAsync('SELECT * FROM users WHERE reset_token_hash = ?', [tokenHash]);
};

db.updateUserPasswordAndClearToken = async function (userId, hashedPassword) {
  return await db.runAsync(
    'UPDATE users SET password = ?, must_change_password = 0, reset_token_hash = NULL, reset_token_expires = NULL WHERE id = ?',
    [hashedPassword, userId]
  );
};

db.updateUserPasswordAndClearFlag = async function (userId, hashedPassword) {
  return await db.runAsync(
    'UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?',
    [hashedPassword, userId]
  );
};

db.updateUserPassword = async function (userId, hashedPassword) {
  return await db.runAsync(
    'UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?',
    [hashedPassword, userId]
  );
};

db.clearMustChangePasswordFlag = async function (userId) {
  return await db.runAsync(
    'UPDATE users SET must_change_password = 0 WHERE id = ?',
    [userId]
  );
};

/* ==========================================================================
   SECURITY QUESTION HELPER FUNCTIONS
   ========================================================================== */

db.getSecurityQuestionsByUserId = async function (userId) {
  const sql = `
    SELECT question_1, question_2 
    FROM user_security_questions 
    WHERE user_id = ?
  `;
  return await db.getAsync(sql, [userId]);
};

db.getUserSecurityQuestions = async function (userId) {
  const record = await db.getAsync(
    'SELECT question_1, question_2 FROM user_security_questions WHERE user_id = ?',
    [userId]
  );
  if (!record) return [];
  return [
    { id: 1, question: record.question_1 },
    { id: 2, question: record.question_2 }
  ];
};

db.saveUserSecurityQuestions = async function (userId, questionsArray) {
  if (!Array.isArray(questionsArray) || questionsArray.length < 2) {
    throw new Error('Two security questions are required');
  }

  const q1 = questionsArray[0].question;
  const a1Hash = questionsArray[0].answerHash;
  const q2 = questionsArray[1].question;
  const a2Hash = questionsArray[1].answerHash;

  const sql = `
    INSERT INTO user_security_questions (user_id, question_1, answer_1_hash, question_2, answer_2_hash)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      question_1 = excluded.question_1,
      answer_1_hash = excluded.answer_1_hash,
      question_2 = excluded.question_2,
      answer_2_hash = excluded.answer_2_hash
  `;
  return await db.runAsync(sql, [userId, q1, a1Hash, q2, a2Hash]);
};

db.setSecurityQuestions = async function (userId, q1, a1Raw, q2, a2Raw) {
  const a1Hash = await bcrypt.hash(a1Raw.toLowerCase().trim(), 10);
  const a2Hash = await bcrypt.hash(a2Raw.toLowerCase().trim(), 10);

  return await db.saveUserSecurityQuestions(userId, [
    { question: q1, answerHash: a1Hash },
    { question: q2, answerHash: a2Hash }
  ]);
};

db.verifySecurityAnswers = async function (userId, a1Raw, a2Raw) {
  const record = await db.getAsync('SELECT * FROM user_security_questions WHERE user_id = ?', [userId]);
  if (!record) return false;

  const valid1 = await bcrypt.compare(a1Raw.toLowerCase().trim(), record.answer_1_hash);
  const valid2 = await bcrypt.compare(a2Raw.toLowerCase().trim(), record.answer_2_hash);

  return valid1 && valid2;
};

/* ==========================================================================
   USER MANAGEMENT HELPER FUNCTIONS
   ========================================================================== */

db.getUsers = async function () {
  const sql = `
    SELECT u.id, u.name, u.email, u.role, u.manager_id, u.subsidiary, u.department, u.access_helpdesk, u.access_assets, u.must_change_password, u.created_at,
           m.name AS manager_name
    FROM users u
    LEFT JOIN users m ON u.manager_id = m.id
    ORDER BY u.id DESC
  `;
  return await db.allAsync(sql);
};

db.getUserById = async function (id) {
  const sql = `
    SELECT u.id, u.name, u.email, u.role, u.manager_id, u.subsidiary, u.department, u.access_helpdesk, u.access_assets, u.must_change_password, u.created_at,
           m.name AS manager_name
    FROM users u
    LEFT JOIN users m ON u.manager_id = m.id
    WHERE u.id = ?
  `;
  return await db.getAsync(sql, [id]);
};

db.createUser = async function ({ name, email, password, role = 'requester', manager_id = null, subsidiary = null, department = null }) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = `
    INSERT INTO users (
      name, email, password, role, manager_id, subsidiary, department, 
      access_helpdesk, access_assets, must_change_password
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, 1)
  `;
  return await db.runAsync(sql, [
    name, 
    email.toLowerCase().trim(), 
    hashedPassword, 
    role, 
    manager_id, 
    subsidiary, 
    department
  ]);
};

/* ==========================================================================
   ASSET MANAGEMENT HELPER FUNCTIONS
   ========================================================================== */

db.getAssets = async function ({ search = '', status = '' } = {}) {
  let sql = `
    SELECT 
      a.id, a.asset_tag, a.category, a.model, a.serial_number, a.status,
      a.assigned_to, a.cost, a.salvage_value, a.po_number, a.vendor, a.location,
      a.purchase_date, a.warranty_expiry, a.last_repair_date, a.refreshed_at, a.created_at,
      u.name AS assigned_user_name, u.email AS assigned_user_email
    FROM assets a
    LEFT JOIN users u ON a.assigned_to = u.id
    WHERE 1=1
  `;
  const params = [];

  if (status) {
    sql += ` AND a.status = ?`;
    params.push(status);
  }

  if (search) {
    sql += ` AND (
      a.asset_tag LIKE ? OR a.model LIKE ? OR a.serial_number LIKE ? OR 
      a.po_number LIKE ? OR a.vendor LIKE ? OR a.location LIKE ? OR u.name LIKE ?
    )`;
    const searchPattern = `%${search.trim()}%`;
    params.push(searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern);
  }

  sql += ` ORDER BY a.id DESC`;
  return await db.allAsync(sql, params);
};

db.getAssetById = async function (id) {
  const sql = `
    SELECT 
      a.id, a.asset_tag, a.category, a.model, a.serial_number, a.status,
      a.assigned_to, a.cost, a.salvage_value, a.po_number, a.vendor, a.location,
      a.purchase_date, a.warranty_expiry, a.last_repair_date, a.refreshed_at, a.created_at,
      u.name AS assigned_user_name, u.email AS assigned_user_email
    FROM assets a
    LEFT JOIN users u ON a.assigned_to = u.id
    WHERE a.id = ?
  `;
  return await db.getAsync(sql, [id]);
};

db.createAsset = async function ({
  asset_tag, category, model, serial_number, status,
  assigned_to, cost, salvage_value, po_number, vendor, location,
  purchase_date, warranty_expiry
}) {
  const sql = `
    INSERT INTO assets (
      asset_tag, category, model, serial_number, status, 
      assigned_to, cost, salvage_value, po_number, vendor, location, 
      purchase_date, warranty_expiry
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  return await db.runAsync(sql, [
    asset_tag, category, model, serial_number || null, status || 'In Stock',
    assigned_to || null, cost ? parseFloat(cost) : 0, salvage_value ? parseFloat(salvage_value) : 0,
    po_number || null, vendor || null, location || null, purchase_date || null, warranty_expiry || null
  ]);
};

db.updateAsset = async function (
  id,
  { category, model, serial_number, status, assigned_to, cost, salvage_value, po_number, vendor, location, purchase_date, warranty_expiry, last_repair_date }
) {
  const sql = `
    UPDATE assets 
    SET category = ?, model = ?, serial_number = ?, status = ?, 
        assigned_to = ?, cost = ?, salvage_value = ?, po_number = ?, vendor = ?, 
        location = ?, purchase_date = ?, warranty_expiry = ?, last_repair_date = COALESCE(?, last_repair_date)
    WHERE id = ?
  `;
  return await db.runAsync(sql, [
    category, model, serial_number || null, status || 'In Stock',
    assigned_to || null, cost ? parseFloat(cost) : 0, salvage_value ? parseFloat(salvage_value) : 0,
    po_number || null, vendor || null, location || null, purchase_date || null, warranty_expiry || null,
    last_repair_date || null, id
  ]);
};

db.reassignAsset = async function (id, assigned_to, location = null) {
  const status = assigned_to ? 'Assigned' : 'In Stock';
  const sql = `
    UPDATE assets
    SET assigned_to = ?, status = ?, location = COALESCE(?, location)
    WHERE id = ?
  `;
  return await db.runAsync(sql, [assigned_to || null, status, location, id]);
};

db.refreshAsset = async function (id, salvage_value) {
  const sql = `
    UPDATE assets
    SET status = 'Refreshed', assigned_to = NULL, salvage_value = ?, refreshed_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `;
  return await db.runAsync(sql, [salvage_value ? parseFloat(salvage_value) : 0, id]);
};

db.deleteAsset = async function (id) {
  return await db.runAsync('DELETE FROM assets WHERE id = ?', [id]);
};

/* ==========================================================================
   ASSET REPAIR LOG HELPER FUNCTIONS
   ========================================================================== */

db.addAssetRepairLog = async function ({
  asset_id, repair_start_date, issue_description, repair_cost, repaired_by
}) {
  const sql = `
    INSERT INTO asset_repair_logs (
      asset_id, repair_start_date, issue_description, repair_cost, repaired_by, status
    )
    VALUES (?, ?, ?, ?, ?, 'In Progress')
  `;
  const result = await db.runAsync(sql, [
    asset_id, repair_start_date, issue_description, repair_cost ? parseFloat(repair_cost) : 0, repaired_by || null
  ]);

  await db.runAsync(
    `UPDATE assets SET status = 'Under Repair', last_repair_date = ? WHERE id = ?`,
    [repair_start_date, asset_id]
  );

  return result;
};

db.getRepairLogsByAssetId = async function (asset_id) {
  const sql = `
    SELECT * FROM asset_repair_logs 
    WHERE asset_id = ? 
    ORDER BY repair_start_date DESC
  `;
  return await db.allAsync(sql, [asset_id]);
};

db.completeAssetRepair = async function (log_id, { repair_end_date, repair_cost, status = 'Completed' }) {
  const log = await db.getAsync('SELECT asset_id FROM asset_repair_logs WHERE id = ?', [log_id]);
  if (!log) throw new Error('Repair log record not found');

  const sql = `
    UPDATE asset_repair_logs
    SET repair_end_date = ?, repair_cost = COALESCE(?, repair_cost), status = ?
    WHERE id = ?
  `;
  const result = await db.runAsync(sql, [repair_end_date, repair_cost ? parseFloat(repair_cost) : null, status, log_id]);

  if (status === 'Completed') {
    await db.runAsync(`UPDATE assets SET status = 'In Stock' WHERE id = ?`, [log.asset_id]);
  }

  return result;
};

module.exports = db;