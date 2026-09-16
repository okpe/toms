const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cron = require('node-cron');
const db = require('./database');
const authRoutes = require('./authRoutes');

// Import modular Auth Guards
const {
  requireAuth,
  requireAdmin,
  requireAdminOrSuper,
  requireManager,
  requireAssetManager,
  requireHelpdeskAccess,
  requireAssetAccess
} = require('./auth-guard');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable proxy trusting for secure cookies on Vercel
app.set('trust proxy', 1);

// Helper function to sanitize CSV fields against Formula Injection
const sanitizeCsvField = (val) => {
  let str = (val || '').toString();
  str = str.replace(/"/g, '""');
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'` + str;
  }
  return `"${str}"`;
};

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true
}));

// ================= TURSO SESSION STORE =================
class TursoSessionStore extends session.Store {
  constructor(database) {
    super();
    this.db = database;
  }

  async get(sid, callback) {
    try {
      const row = await this.db.getAsync(
        `SELECT sess FROM sessions WHERE sid = ? AND datetime(expired) > datetime('now')`,
        [sid]
      );
      if (!row) return callback(null, null);
      const sessionData = JSON.parse(row.sess);
      callback(null, sessionData);
    } catch (err) {
      callback(err);
    }
  }

  async set(sid, sessionData, callback) {
    try {
      const maxAge = sessionData.cookie?.maxAge || 86400000;
      const expired = new Date(Date.now() + maxAge).toISOString();
      const sessStr = JSON.stringify(sessionData);

      await this.db.runAsync(
        `INSERT INTO sessions (sid, sess, expired) VALUES (?, ?, ?)
         ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expired = excluded.expired`,
        [sid, sessStr, expired]
      );
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  async destroy(sid, callback) {
    try {
      await this.db.runAsync(`DELETE FROM sessions WHERE sid = ?`, [sid]);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }
}

// Session Middleware Configuration with Turso Store
app.use(
  session({
    store: new TursoSessionStore(db),
    name: 'connect.sid',
    secret: process.env.SESSION_SECRET || 'fallback-secret-key-change-in-env',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' || !!process.env.VERCEL,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  })
);

// Serve static assets
app.use(express.static(path.join(__dirname, 'public')));

// Mount modular auth router for auxiliary auth actions
app.use('/api/auth', authRoutes);

// Root URL redirect
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// ================= SECURED DIAGNOSTIC ENDPOINTS =================

app.get('/api/nuke-session', requireAuth, (req, res) => {
  if (req.session) {
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.send('<h1>Session Nuke Complete!</h1><p><a href="/login.html">Click here to log in</a></p>');
    });
  } else {
    res.send('<h1>No active session.</h1><p><a href="/login.html">Click here to log in</a></p>');
  }
});

// ================= AUTHENTICATION HANDLERS =================

const loginHandler = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const normalizedRole = String(user.role || '').trim().toLowerCase();
    const isSuperOrAdmin = ['admin', 'super_admin', 'superadmin'].includes(normalizedRole);
    const hasQuestions = user.security_questions_set === 1;

    req.session.userId = user.id;
    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      subsidiary: user.subsidiary || null,
      department: user.department || null,
      role: normalizedRole,
      access_helpdesk: isSuperOrAdmin ? 1 : (user.access_helpdesk ?? 1),
      access_assets: isSuperOrAdmin ? 1 : (user.access_assets ?? 0),
      mustChangePassword: user.must_change_password === 1,
      securityQuestionsSet: hasQuestions,
      requireSecuritySetup: !hasQuestions,
      has_security_questions: hasQuestions
    };

    req.session.save((err) => {
      if (err) {
        console.error('[!] Session save failed during login:', err);
        return res.status(500).json({ error: 'Failed to save session' });
      }

      const mustChange = user.must_change_password === 1;

      res.json({ 
        success: true,
        message: 'Login successful', 
        user: req.session.user,
        userId: user.id,
        requiresFirstTimeSetup: mustChange,
        mustChangePassword: mustChange,
        must_change_password: mustChange,
        securityQuestionsSet: hasQuestions,
        requireSecuritySetup: !hasQuestions,
        has_security_questions: hasQuestions
      });
    });
  } catch (err) {
    console.error('[!] Login error:', err);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
};

app.post('/api/login', loginHandler);
app.post('/api/auth/login', loginHandler);

// First-Time Setup Route
app.post('/api/auth/first-time-setup', async (req, res) => {
  try {
    const userId = req.body.userId || req.body.id || req.session?.userId || req.session?.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Session expired or invalid user ID.' });
    }

    const { new_password, question_1, answer_1, question_2, answer_2 } = req.body;

    if (!new_password || !question_1 || !answer_1 || !question_2 || !answer_2) {
      return res.status(400).json({ error: 'Please fill in all security questions and a new password.' });
    }

    const hashedNewPassword = await bcrypt.hash(new_password, 10);

    // Save security questions
    await db.setSecurityQuestions(userId, question_1.trim(), answer_1.trim(), question_2.trim(), answer_2.trim());

    // Update password and clear must_change_password flag
    await db.updateUserPasswordAndClearFlag(userId, hashedNewPassword);

    if (req.session.user) {
      req.session.user.mustChangePassword = false;
      req.session.user.securityQuestionsSet = true;
      req.session.user.requireSecuritySetup = false;
      req.session.user.has_security_questions = true;
      req.session.save(() => {});
    }

    res.json({ success: true, message: 'Account setup completed successfully!' });
  } catch (err) {
    console.error('Setup error:', err);
    res.status(500).json({ error: 'Failed to complete setup.' });
  }
});

// ================= SECURITY QUESTION & RECOVERY ENDPOINTS =================

app.get('/api/auth/security-questions', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email address is required.' });

    const user = await db.findUserByEmail(email.trim());
    if (!user) {
      return res.status(404).json({ error: 'No account found with that email address.' });
    }

    const sq = await db.getAsync('SELECT question_1, question_2 FROM user_security_questions WHERE user_id = ?', [user.id]);
    if (!sq) {
      return res.status(422).json({ 
        error: 'Security questions have not been configured for this account. Please contact your System Administrator.' 
      });
    }

    return res.status(200).json({ 
      question_1: sq.question_1, 
      question_2: sq.question_2,
      question1: sq.question_1, 
      question2: sq.question_2 
    });
  } catch (err) {
    console.error('[!] Get security questions query error:', err);
    return res.status(500).json({ error: 'An unexpected system error occurred.' });
  }
});

app.post('/api/auth/get-security-questions', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const user = await db.findUserByEmail(email.trim());
    if (!user) return res.status(404).json({ error: 'No account found with that email.' });

    const sq = await db.getAsync('SELECT question_1, question_2 FROM user_security_questions WHERE user_id = ?', [user.id]);
    if (!sq) {
      return res.status(422).json({ 
        error: 'Security questions have not been configured for this account.' 
      });
    }

    return res.status(200).json({ 
      question_1: sq.question_1, 
      question_2: sq.question_2,
      question1: sq.question_1, 
      question2: sq.question_2 
    });
  } catch (err) {
    console.error('[!] Get security questions error:', err);
    return res.status(500).json({ error: 'Failed to retrieve security questions.' });
  }
});

const setupSecurityQuestionsHandler = async (req, res) => {
  try {
    const userId = req.session?.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized session.' });
    }

    let q1 = req.body.question1;
    let a1 = req.body.answer1;
    let q2 = req.body.question2;
    let a2 = req.body.answer2;

    if (Array.isArray(req.body.questions) && req.body.questions.length >= 2) {
      q1 = q1 || req.body.questions[0].question;
      a1 = a1 || req.body.questions[0].answer;
      q2 = q2 || req.body.questions[1].question;
      a2 = a2 || req.body.questions[1].answer;
    }

    if (!q1 || !a1 || !q2 || !a2) {
      return res.status(400).json({ error: 'All security questions and answers are required.' });
    }

    const answer1Hash = await bcrypt.hash(a1.trim().toLowerCase(), 10);
    const answer2Hash = await bcrypt.hash(a2.trim().toLowerCase(), 10);

    await db.runAsync('DELETE FROM user_security_questions WHERE user_id = ?', [userId]);
    await db.runAsync(
      `INSERT INTO user_security_questions (user_id, question_1, answer_1_hash, question_2, answer_2_hash) VALUES (?, ?, ?, ?, ?)`,
      [userId, q1, answer1Hash, q2, answer2Hash]
    );

    await db.runAsync('UPDATE users SET security_questions_set = 1 WHERE id = ?', [userId]);
    
    req.session.user.securityQuestionsSet = true;
    req.session.user.requireSecuritySetup = false;
    req.session.user.has_security_questions = true;

    req.session.save((err) => {
      if (err) console.error('[!] Session save warning during setup security:', err);
      return res.status(200).json({ success: true, message: 'Security questions configured successfully.' });
    });
  } catch (err) {
    console.error('[!] Setup security questions error:', err);
    return res.status(500).json({ error: 'Failed to save security questions.' });
  }
};

app.post('/api/auth/setup-security-questions', requireAuth, setupSecurityQuestionsHandler);

const verifyAndResetPasswordHandler = async (req, res) => {
  try {
    const { email, answer1, answer2, newPassword } = req.body;

    if (!email || !answer1 || !answer2 || !newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'All fields are required and new password must be at least 8 characters.' });
    }

    const user = await db.findUserByEmail(email.trim());
    if (!user) return res.status(400).json({ error: 'Invalid reset request.' });

    const sq = await db.getAsync('SELECT * FROM user_security_questions WHERE user_id = ?', [user.id]);
    if (!sq) return res.status(400).json({ error: 'Security questions not set up for this account.' });

    const match1 = await bcrypt.compare(answer1.trim().toLowerCase(), sq.answer_1_hash);
    const match2 = await bcrypt.compare(answer2.trim().toLowerCase(), sq.answer_2_hash);

    if (!match1 || !match2) {
      return res.status(400).json({ error: 'Incorrect security question answers.' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.runAsync('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?', [newHash, user.id]);

    return res.status(200).json({ success: true, message: 'Password reset successful.' });
  } catch (err) {
    console.error('[!] Verify and reset error:', err);
    return res.status(500).json({ error: 'Failed to reset password.' });
  }
};

app.post('/api/auth/reset-password-security', verifyAndResetPasswordHandler);
app.post('/api/auth/verify-and-reset', verifyAndResetPasswordHandler);
app.post('/api/auth/request-password-reset', verifyAndResetPasswordHandler);

// Authenticated Password Update Endpoint
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body;
  const userId = req.session.user.id;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.runAsync(
      `UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?`,
      [hashedPassword, userId]
    );

    req.session.user.mustChangePassword = false;
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: 'Failed to update session.' });
      res.json({ message: 'Password updated successfully.' });
    });
  } catch (err) {
    console.error('[!] Change password error:', err);
    res.status(500).json({ error: 'Failed to update password.' });
  }
});

// Session Verification Endpoint
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const userId = req.session?.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Invalid session structure. Please log in again.' });
    }

    const user = await db.getAsync(
      'SELECT id, name, email, subsidiary, department, role, access_helpdesk, access_assets, must_change_password, security_questions_set FROM users WHERE id = ?',
      [userId]
    );

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'User account no longer exists' });
    }

    const normalizedRole = String(user.role || '').trim().toLowerCase();
    const isSuperOrAdmin = ['admin', 'super_admin', 'superadmin'].includes(normalizedRole);
    const hasQuestions = user.security_questions_set === 1;

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      subsidiary: user.subsidiary || null,
      department: user.department || null,
      role: normalizedRole,
      access_helpdesk: isSuperOrAdmin ? 1 : (user.access_helpdesk ?? 1),
      access_assets: isSuperOrAdmin ? 1 : (user.access_assets ?? 0),
      mustChangePassword: user.must_change_password === 1,
      securityQuestionsSet: hasQuestions,
      requireSecuritySetup: !hasQuestions,
      has_security_questions: hasQuestions
    };

    req.session.save((err) => {
      if (err) {
        console.error('[!] meHandler session save error:', err);
        return res.status(500).json({ error: 'Failed to update session state' });
      }

      res.json({ 
        id: req.session.user.id,
        name: req.session.user.name,
        email: req.session.user.email,
        subsidiary: req.session.user.subsidiary,
        department: req.session.user.department,
        role: req.session.user.role,
        access_helpdesk: req.session.user.access_helpdesk,
        access_assets: req.session.user.access_assets,
        mustChangePassword: req.session.user.mustChangePassword,
        must_change_password: req.session.user.mustChangePassword,
        securityQuestionsSet: req.session.user.securityQuestionsSet,
        requireSecuritySetup: req.session.user.requireSecuritySetup,
        has_security_questions: req.session.user.has_security_questions,
        user: req.session.user
      });
    });
  } catch (err) {
    console.error('[!] meHandler DB error:', err);
    res.status(500).json({ error: 'Server error retrieving session user' });
  }
});

// Logout Handler
app.all('/api/auth/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Could not log out' });
      }
      res.clearCookie('connect.sid');
      return res.status(200).json({ message: 'Logged out successfully' });
    });
  } else {
    return res.status(200).json({ message: 'No active session' });
  }
});

// ================= ADMIN USER MANAGEMENT ROUTES =================

app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdminOrSuper, async (req, res) => {
  const userId = req.params.id;

  try {
    const targetUser = await db.getAsync('SELECT role FROM users WHERE id = ?', [userId]);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    const tempPassword = 'Temp#' + crypto.randomBytes(4).toString('hex');
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    await db.runAsync(
      `UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?`,
      [hashedPassword, userId]
    );

    res.json({ message: 'Password reset successfully', tempPassword });
  } catch (err) {
    console.error('[!] Admin password reset error:', err);
    res.status(500).json({ error: 'Failed to reset user password' });
  }
});

app.get('/api/admin/users', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const rows = await db.allAsync(`
      SELECT u.id, u.name, u.email, u.subsidiary, u.department, u.role, u.manager_id, 
             u.access_helpdesk, u.access_assets, u.created_at, m.name as manager_name
      FROM users u
      LEFT JOIN users m ON u.manager_id = m.id
      ORDER BY u.id DESC
    `);
    res.json(rows || []);
  } catch (err) {
    console.error('[!] Error fetching admin users:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/tickets', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const rows = await db.allAsync(`
      SELECT t.id, t.ticket_number, t.title, t.category, t.priority, t.status, t.created_at, u.name as requester_name
      FROM tickets t
      LEFT JOIN users u ON t.requester_id = u.id
      ORDER BY t.id DESC
    `);
    res.json(rows || []);
  } catch (err) {
    console.error('[!] Error fetching admin tickets:', err);
    res.status(500).json({ error: 'Failed to fetch admin tickets' });
  }
});

app.get('/api/admin/assets', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const rows = await db.allAsync(`
      SELECT a.id, a.asset_tag, a.category, a.model, a.serial_number, a.status, u.name as assigned_user_name
      FROM assets a
      LEFT JOIN users u ON a.assigned_to = u.id
      ORDER BY a.id DESC
    `);
    res.json(rows || []);
  } catch (err) {
    console.error('[!] Error fetching admin assets:', err);
    res.status(500).json({ error: 'Failed to fetch admin assets' });
  }
});

app.get('/api/admin/users/:id', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const user = await db.getAsync(
      'SELECT id, name, email, subsidiary, department, role, manager_id, access_helpdesk, access_assets, created_at FROM users WHERE id = ?',
      [req.params.id]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

app.get('/api/admin/managers', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const rows = await db.allAsync(`SELECT id, name, email FROM users WHERE LOWER(role) = 'manager' ORDER BY name ASC`);
    res.json(rows || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/users', requireAuth, requireAdminOrSuper, async (req, res) => {
  const { name, email, password, subsidiary, department, role, manager_id, access_helpdesk, access_assets } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'Name, email, password, and role are required' });
  }

  const sessionRole = String(req.session.user.role || '').toLowerCase();
  const newRole = String(role).toLowerCase().trim();

  if (newRole === 'super_admin' && sessionRole !== 'super_admin') {
    return res.status(403).json({ error: 'Only Super Admins can create Super Admin accounts' });
  }

  if (newRole === 'admin' && sessionRole !== 'super_admin') {
    return res.status(403).json({ error: 'Only Super Admins can grant Admin roles' });
  }

  if (newRole === 'requester' && !manager_id) {
    return res.status(400).json({ error: 'Line Manager selection is required for Requester users' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const mId = manager_id ? parseInt(manager_id, 10) : null;
    const allowHelpdesk = (access_helpdesk === true || access_helpdesk === 1 || access_helpdesk === '1') ? 1 : 0;
    const allowAssets = (access_assets === true || access_assets === 1 || access_assets === '1') ? 1 : 0;

    const result = await db.runAsync(
      `INSERT INTO users (name, email, password, subsidiary, department, role, manager_id, access_helpdesk, access_assets, must_change_password) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [name, email.toLowerCase().trim(), hashedPassword, subsidiary || null, department || null, newRole, mId, allowHelpdesk, allowAssets]
    );

    res.status(201).json({ message: 'User created successfully', userId: result.id });
  } catch (error) {
    res.status(400).json({
      error: error.message.includes('UNIQUE') ? 'Email address is already registered' : 'Failed to create user'
    });
  }
});

app.put('/api/admin/users/:id', requireAuth, requireAdminOrSuper, async (req, res) => {
  const userId = req.params.id;
  const { name, email, subsidiary, department, role, manager_id, access_helpdesk, access_assets, password } = req.body;

  try {
    const targetUser = await db.getAsync('SELECT role FROM users WHERE id = ?', [userId]);

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const targetRole = String(targetUser.role || '').toLowerCase();
    const sessionRole = String(req.session.user.role || '').toLowerCase();
    const newRole = String(role || '').toLowerCase().trim();

    if (targetRole === 'super_admin') {
      return res.status(403).json({ error: 'Super Administrator accounts are protected and cannot be edited' });
    }

    if ((newRole === 'super_admin' || newRole === 'admin' || targetRole === 'admin') && sessionRole !== 'super_admin') {
      return res.status(403).json({ error: 'Only Super Admins can manage or assign Administrative roles' });
    }

    if (!name || !email || !role) {
      return res.status(400).json({ error: 'Name, email, and role are required' });
    }

    if (newRole === 'requester' && !manager_id) {
      return res.status(400).json({ error: 'Line Manager selection is required for Requester users' });
    }

    const mId = manager_id ? parseInt(manager_id, 10) : null;
    const allowHelpdesk = (access_helpdesk === true || access_helpdesk === 1 || access_helpdesk === '1') ? 1 : 0;
    const allowAssets = (access_assets === true || access_assets === 1 || access_assets === '1') ? 1 : 0;

    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.runAsync(
        `UPDATE users 
         SET name = ?, email = ?, password = ?, subsidiary = ?, department = ?, role = ?, manager_id = ?, access_helpdesk = ?, access_assets = ? 
         WHERE id = ?`,
        [name, email.toLowerCase().trim(), hashedPassword, subsidiary || null, department || null, newRole, mId, allowHelpdesk, allowAssets, userId]
      );
    } else {
      await db.runAsync(
        `UPDATE users 
         SET name = ?, email = ?, subsidiary = ?, department = ?, role = ?, manager_id = ?, access_helpdesk = ?, access_assets = ? 
         WHERE id = ?`,
        [name, email.toLowerCase().trim(), subsidiary || null, department || null, newRole, mId, allowHelpdesk, allowAssets, userId]
      );
    }

    res.json({ message: 'User and permissions updated successfully' });
  } catch (error) {
    res.status(400).json({
      error: error.message.includes('UNIQUE') ? 'Email is already in use' : 'Failed to update user'
    });
  }
});

app.delete('/api/admin/users/:id', requireAuth, requireAdminOrSuper, async (req, res) => {
  const userId = req.params.id;

  try {
    const targetUser = await db.getAsync('SELECT role FROM users WHERE id = ?', [userId]);

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const targetRole = String(targetUser.role || '').toLowerCase();
    const sessionRole = String(req.session.user.role || '').toLowerCase();

    if (targetRole === 'super_admin') {
      return res.status(403).json({ error: 'Super Administrator accounts cannot be deleted' });
    }

    if (targetRole === 'admin' && sessionRole !== 'super_admin') {
      return res.status(403).json({ error: 'Only Super Admins can delete Admin accounts' });
    }

    await db.runAsync('DELETE FROM users WHERE id = ?', [userId]);
    res.json({ message: 'User account deleted successfully' });
  } catch (err) {
    console.error('[!] Error deleting user:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ================= TICKET ROUTES =================

app.post('/api/tickets', requireAuth, requireHelpdeskAccess, async (req, res) => {
  const { title, description, category, priority, ticket_type, subsidiary, department } = req.body;
  const userId = req.session.user.id;
  const userRole = String(req.session.user.role || '').toLowerCase();

  if (!title || !description) {
    return res.status(400).json({ error: 'Title and description are required' });
  }

  const finalSubsidiary = subsidiary || req.session.user.subsidiary || null;
  const finalDepartment = department || req.session.user.department || null;

  let selectedType = ticket_type || 'Incident';
  if (selectedType.includes('Incident')) selectedType = 'Incident';
  if (selectedType.includes('Service Request')) selectedType = 'Service Request';
  if (selectedType.includes('Change Request')) selectedType = 'Change Request';

  let initialStatus = 'Open';
  if (['manager', 'admin', 'super_admin', 'superadmin', 'resolver'].includes(userRole)) {
    initialStatus = 'Approved';
  }

  const priorityHours = { Critical: 2, High: 4, Medium: 24, Low: 48 };
  const hoursToAdd = priorityHours[priority] || 24;
  const now = new Date();
  const slaTargetResolution = new Date(now.getTime() + hoursToAdd * 60 * 60 * 1000).toISOString();

  try {
    const insertQuery = `
      INSERT INTO tickets (
        ticket_type, title, description, category, priority, status, 
        requester_id, subsidiary, department, created_at, updated_at, sla_target_resolution
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const result = await db.runAsync(insertQuery, [
      selectedType, title, description, category || 'General Support',
      priority || 'Medium', initialStatus, userId, finalSubsidiary, finalDepartment,
      now.toISOString(), now.toISOString(), slaTargetResolution
    ]);

    const ticketId = result.id;
    let prefix = 'INC';
    if (selectedType === 'Service Request') prefix = 'SR';
    if (selectedType === 'Change Request') prefix = 'CR';

    const ticketNumber = `${prefix}${String(ticketId).padStart(5, '0')}`;

    await db.runAsync(
      `UPDATE tickets SET ticket_number = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [ticketNumber, ticketId]
    );

    res.status(201).json({ message: 'Ticket created successfully', ticketId, ticketNumber, status: initialStatus });
  } catch (err) {
    console.error('[!] Error inserting ticket:', err);
    res.status(500).json({ error: 'Failed to create ticket' });
  }
});

app.get('/api/tickets/my-tickets', requireAuth, requireHelpdeskAccess, async (req, res) => {
  const userId = req.session.user.id;
  try {
    const rows = await db.allAsync(
      `SELECT id, ticket_number, ticket_type, title, description, category, priority, status, created_at, updated_at
       FROM tickets WHERE requester_id = ? ORDER BY id DESC`,
      [userId]
    );
    res.json(rows || []);
  } catch (err) {
    console.error('Error fetching tickets:', err);
    res.status(500).json({ error: 'Failed to fetch tickets' });
  }
});

app.get('/api/tickets/:id', requireAuth, requireHelpdeskAccess, async (req, res) => {
  const ticketId = req.params.id;
  const user = req.session.user;

  try {
    const ticket = await db.getAsync(
      `SELECT t.*, u.name as requester_name, u.email as requester_email, u.manager_id as requester_manager_id 
       FROM tickets t JOIN users u ON t.requester_id = u.id WHERE t.id = ?`,
      [ticketId]
    );

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const userRole = String(user.role || '').toLowerCase();
    const isAdmin = ['admin', 'super_admin', 'superadmin'].includes(userRole);
    const isOwner = ticket.requester_id === user.id;
    const isDirectManager = userRole === 'manager' && ticket.requester_manager_id === user.id;

    if (!isAdmin && !isOwner && !isDirectManager) {
      return res.status(403).json({ error: 'Access denied to this ticket' });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve ticket details' });
  }
});

app.put('/api/tickets/:id', requireAuth, requireHelpdeskAccess, async (req, res) => {
  const ticketId = req.params.id;
  const { title, description, category, priority } = req.body;
  const userId = req.session.user.id;
  const userRole = String(req.session.user.role || '').toLowerCase();

  try {
    const ticket = await db.getAsync('SELECT * FROM tickets WHERE id = ?', [ticketId]);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    const isStaff = ['admin', 'super_admin', 'superadmin'].includes(userRole);
    if (!isStaff && ticket.requester_id !== userId) {
      return res.status(403).json({ error: 'Permission denied to edit this ticket' });
    }

    await db.runAsync(
      `UPDATE tickets SET title = COALESCE(?, title), description = COALESCE(?, description), 
       category = COALESCE(?, category), priority = COALESCE(?, priority), updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [title, description, category, priority, ticketId]
    );

    res.json({ message: 'Ticket updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update ticket details' });
  }
});

app.put('/api/tickets/:id/confirm', requireAuth, requireHelpdeskAccess, async (req, res) => {
  const ticketId = req.params.id;
  const { action } = req.body;
  const userId = req.session.user.id;

  if (!['Confirm', 'Reopen'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action. Must be Confirm or Reopen.' });
  }

  const newStatus = action === 'Confirm' ? 'Closed' : 'In Progress';
  const now = new Date().toISOString();

  try {
    const result = await db.runAsync(
      `UPDATE tickets 
       SET status = ?, closed_at = CASE WHEN ? = 'Closed' THEN ? ELSE closed_at END, updated_at = CURRENT_TIMESTAMP
       WHERE id = ? AND requester_id = ?`,
      [newStatus, newStatus, now, ticketId, userId]
    );

    if (result.changes === 0) {
      return res.status(400).json({ error: 'Failed to update ticket confirmation' });
    }

    res.json({ message: action === 'Confirm' ? 'Ticket closed successfully' : 'Ticket reopened for further work' });
  } catch (err) {
    res.status(500).json({ error: 'Database update failed' });
  }
});

app.delete('/api/tickets/:id', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const result = await db.runAsync('DELETE FROM tickets WHERE id = ?', [req.params.id]);
    if (result.changes === 0) return res.status(404).json({ error: 'Ticket not found' });
    res.json({ message: 'Ticket deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete ticket' });
  }
});

// ================= MANAGER ROUTES =================

app.get('/api/manager/tickets', requireAuth, requireManager, requireHelpdeskAccess, async (req, res) => {
  const userRole = String(req.session.user.role || '').toLowerCase();
  const managerId = req.session.user.id;
  const isAdmin = ['admin', 'super_admin', 'superadmin'].includes(userRole);

  const query = isAdmin
    ? `SELECT t.id, t.ticket_number, t.ticket_type, t.title, t.description, t.category, t.priority, t.status, t.created_at, t.updated_at, t.requester_id,
              u.name as requester_name, u.email as requester_email
       FROM tickets t JOIN users u ON t.requester_id = u.id ORDER BY t.id DESC`
    : `SELECT t.id, t.ticket_number, t.ticket_type, t.title, t.description, t.category, t.priority, t.status, t.created_at, t.updated_at, t.requester_id,
              u.name as requester_name, u.email as requester_email
       FROM tickets t JOIN users u ON t.requester_id = u.id 
       WHERE u.manager_id = ? OR t.requester_id = ? 
       ORDER BY t.id DESC`;

  try {
    const rows = await db.allAsync(query, isAdmin ? [] : [managerId, managerId]);
    res.json(rows || []);
  } catch (err) {
    console.error('Error fetching manager tickets:', err);
    res.status(500).json({ error: 'Failed to retrieve tickets' });
  }
});

app.put('/api/manager/tickets/:id/action', requireAuth, requireManager, requireHelpdeskAccess, async (req, res) => {
  const ticketId = req.params.id;
  const { action } = req.body;

  if (!['Approved', 'Rejected'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action. Must be Approved or Rejected.' });
  }

  try {
    const ticket = await db.getAsync('SELECT id FROM tickets WHERE id = ?', [ticketId]);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    await db.runAsync(`UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [action, ticketId]);
    res.json({ message: `Ticket status successfully updated to ${action}` });
  } catch (err) {
    console.error('Error updating ticket status:', err);
    res.status(500).json({ error: err.message || 'Failed to update ticket' });
  }
});

// ================= RESOLVER / WORKITEM ROUTES =================

const getResolverTicketsHandler = async (req, res) => {
  try {
    const { status } = req.query;
    let sql = `
      SELECT t.id, t.ticket_number, t.ticket_type, t.title, t.description, t.category, t.priority, t.status, t.created_at, t.updated_at,
             t.sla_target_resolution, t.sla_resolution_status, u.name as requester_name, u.email as requester_email
      FROM tickets t JOIN users u ON t.requester_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status && status.toUpperCase() !== 'ALL') {
      sql += ` AND t.status = ?`;
      params.push(status);
    } else if (!status) {
      sql += ` AND t.status IN ('Approved', 'Open', 'In Progress', 'Resolved', 'Closed')`;
    }

    sql += ` ORDER BY t.id DESC`;

    const rows = await db.allAsync(sql, params);
    res.json(rows || []);
  } catch (err) {
    console.error('Error fetching admin ticket queue:', err);
    res.status(500).json({ error: 'Failed to retrieve ticket queue' });
  }
};

const updateResolverTicketStatusHandler = async (req, res) => {
  const ticketId = req.params.id;
  const { status, resolution_notes } = req.body;

  if (!['In Progress', 'Resolved'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status update.' });
  }

  if (status === 'Resolved' && (!resolution_notes || resolution_notes.trim().length < 10)) {
    return res.status(400).json({ error: 'Resolution notes (min 10 characters) detailing the fix are required.' });
  }

  const now = new Date();
  const nowIso = now.toISOString();

  try {
    const ticket = await db.getAsync(`SELECT sla_target_resolution FROM tickets WHERE id = ?`, [ticketId]);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    let slaStatus = 'Pending';
    if (status === 'Resolved') {
      const isBreached = ticket.sla_target_resolution && now > new Date(ticket.sla_target_resolution);
      slaStatus = isBreached ? 'Breached' : 'Met';
    }

    const updateQuery = `
      UPDATE tickets 
      SET status = ?, resolution_notes = COALESCE(?, resolution_notes),
          resolved_at = CASE WHEN ? = 'Resolved' THEN ? ELSE resolved_at END,
          sla_resolution_status = CASE WHEN ? = 'Resolved' THEN ? ELSE sla_resolution_status END,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;

    await db.runAsync(updateQuery, [status, resolution_notes || null, status, nowIso, status, slaStatus, ticketId]);
    res.json({ message: `Ticket updated to ${status}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update ticket status' });
  }
};

app.get('/api/resolver/tickets', requireAuth, requireAdmin, requireHelpdeskAccess, getResolverTicketsHandler);
app.get('/api/admin/tickets/queue', requireAuth, requireAdmin, requireHelpdeskAccess, getResolverTicketsHandler);

app.put('/api/resolver/tickets/:id/status', requireAuth, requireAdmin, requireHelpdeskAccess, updateResolverTicketStatusHandler);
app.put('/api/admin/tickets/:id/status', requireAuth, requireAdmin, requireHelpdeskAccess, updateResolverTicketStatusHandler);

// ================= ASSET MANAGEMENT ROUTES =================

app.get('/api/assets', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  try {
    const { search, status } = req.query;
    const assets = await db.getAssets({ search, status });
    res.json(assets || []);
  } catch (err) {
    console.error('[!] Error fetching assets:', err);
    res.status(500).json({ error: 'Failed to fetch hardware assets' });
  }
});

const assetExportHandler = async (req, res) => {
  const { status, category } = req.query;
  let conditions = [];
  let params = [];

  if (status) { conditions.push('a.status = ?'); params.push(status); }
  if (category) { conditions.push('a.category = ?'); params.push(category); }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  try {
    const rows = await db.allAsync(`
      SELECT 
        a.asset_tag, a.category, a.model, a.serial_number, a.status,
        a.cost, a.salvage_value, a.po_number, a.vendor, a.location,
        u.name as assigned_user_name, u.email as assigned_user_email,
        a.purchase_date, a.warranty_expiry, a.last_repair_date, a.refreshed_at, a.created_at
      FROM assets a LEFT JOIN users u ON a.assigned_to = u.id
      ${whereClause} ORDER BY a.id DESC
    `, params);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=asset_inventory_report_${Date.now()}.csv`);

    let csv = 'Asset Tag,Category,Model,Serial Number,Status,Cost,Salvage Value,PO Number,Vendor,Location,Assigned To (Name),Assigned To (Email),Purchase Date,Warranty Expiry,Last Repair Date,Refreshed At,Created At\n';

    rows.forEach((r) => {
      csv += [
        sanitizeCsvField(r.asset_tag), sanitizeCsvField(r.category), sanitizeCsvField(r.model), sanitizeCsvField(r.serial_number),
        sanitizeCsvField(r.status), sanitizeCsvField(r.cost), sanitizeCsvField(r.salvage_value), sanitizeCsvField(r.po_number), sanitizeCsvField(r.vendor),
        sanitizeCsvField(r.location), sanitizeCsvField(r.assigned_user_name), sanitizeCsvField(r.assigned_user_email),
        sanitizeCsvField(r.purchase_date), sanitizeCsvField(r.warranty_expiry), sanitizeCsvField(r.last_repair_date), sanitizeCsvField(r.refreshed_at), sanitizeCsvField(r.created_at)
      ].join(',') + '\n';
    });

    res.send(csv);
  } catch (err) {
    res.status(500).json({ error: 'Failed to spool asset report CSV' });
  }
};

app.get('/api/assets/export', requireAuth, requireAssetManager, requireAssetAccess, assetExportHandler);
app.get('/api/assets/reports/export', requireAuth, requireAdminOrSuper, assetExportHandler);

app.get('/api/assets/reports', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const summaryQuery = `
      SELECT 
        COUNT(*) as total_assets, 
        COALESCE(SUM(cost), 0) as total_asset_value,
        COALESCE(SUM(salvage_value), 0) as total_salvage_value,
        SUM(CASE WHEN status = 'In Stock' THEN 1 ELSE 0 END) as in_stock_count,
        SUM(CASE WHEN status = 'Assigned' THEN 1 ELSE 0 END) as assigned_count,
        SUM(CASE WHEN status = 'Under Repair' THEN 1 ELSE 0 END) as in_repair_count,
        SUM(CASE WHEN status = 'Retired' THEN 1 ELSE 0 END) as retired_count,
        SUM(CASE WHEN status = 'Refreshed' THEN 1 ELSE 0 END) as refreshed_count,
        SUM(CASE WHEN warranty_expiry IS NOT NULL AND date(warranty_expiry) <= date('now') THEN 1 ELSE 0 END) as expired_warranty_count
      FROM assets
    `;
    const summary = await db.getAsync(summaryQuery);
    res.json({ summary });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate asset report summary' });
  }
});

app.get('/api/assets/:id', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  try {
    const asset = await db.getAssetById(req.params.id);
    if (!asset) return res.status(404).json({ error: 'Asset not found' });
    res.json(asset);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch asset details' });
  }
});

app.post('/api/assets', requireAuth, requireAdminOrSuper, async (req, res) => {
  const { asset_tag, category, model, serial_number, status, assigned_to, purchase_date, warranty_expiry, cost, salvage_value, po_number, vendor, location } = req.body;

  if (!asset_tag || !category || !model) {
    return res.status(400).json({ error: 'Asset Tag, Category, and Model are required' });
  }

  try {
    const assignedUser = assigned_to ? parseInt(assigned_to, 10) : null;
    const initialStatus = assignedUser ? 'Assigned' : (status || 'In Stock');

    const result = await db.createAsset({
      asset_tag: asset_tag.trim(), category, model,
      serial_number: serial_number ? serial_number.trim() : null,
      status: initialStatus, assigned_to: assignedUser,
      cost: cost ? parseFloat(cost) : 0,
      salvage_value: salvage_value ? parseFloat(salvage_value) : 0,
      po_number: po_number ? po_number.trim() : null,
      vendor: vendor ? vendor.trim() : null, location: location ? location.trim() : null,
      purchase_date, warranty_expiry
    });

    res.status(201).json({ message: 'Asset created successfully', assetId: result.id });
  } catch (err) {
    console.error('[!] Error creating asset:', err);
    res.status(400).json({
      error: err.message.includes('UNIQUE') ? 'Asset Tag or Serial Number already exists' : 'Failed to create asset'
    });
  }
});

app.put('/api/assets/:id', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  const assetId = req.params.id;
  const { category, model, serial_number, status, assigned_to, purchase_date, warranty_expiry, cost, salvage_value, po_number, vendor, location, last_repair_date } = req.body;

  if (!category || !model) {
    return res.status(400).json({ error: 'Category and Model are required' });
  }

  try {
    const assignedUser = assigned_to ? parseInt(assigned_to, 10) : null;
    let updatedStatus = status || (assignedUser ? 'Assigned' : 'In Stock');

    const result = await db.updateAsset(assetId, {
      category, model, serial_number: serial_number ? serial_number.trim() : null,
      status: updatedStatus, assigned_to: assignedUser, cost: cost ? parseFloat(cost) : 0,
      salvage_value: salvage_value ? parseFloat(salvage_value) : 0,
      po_number: po_number ? po_number.trim() : null, vendor: vendor ? vendor.trim() : null,
      location: location ? location.trim() : null, purchase_date, warranty_expiry,
      last_repair_date
    });

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Asset not found or no changes made' });
    }

    res.json({ message: 'Asset updated successfully' });
  } catch (err) {
    console.error('[!] Error updating asset:', err);
    res.status(400).json({ error: 'Failed to update asset details' });
  }
});

app.put('/api/assets/:id/refresh', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  const assetId = req.params.id;
  const { salvage_value } = req.body;

  try {
    const result = await db.refreshAsset(assetId, salvage_value);
    if (result.changes === 0) return res.status(404).json({ error: 'Asset not found' });
    res.json({ message: 'Asset refreshed successfully' });
  } catch (err) {
    console.error('[!] Error refreshing asset:', err);
    res.status(500).json({ error: 'Failed to process asset refresh' });
  }
});

app.delete('/api/assets/:id', requireAuth, requireAdminOrSuper, async (req, res) => {
  try {
    const result = await db.deleteAsset(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Asset not found' });
    res.json({ message: 'Asset deleted successfully' });
  } catch (err) {
    console.error('[!] Error deleting asset:', err);
    res.status(500).json({ error: 'Failed to delete asset' });
  }
});

// ================= ASSET REPAIR LOG ROUTES =================

app.get('/api/assets/:id/repairs', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  try {
    const logs = await db.getRepairLogsByAssetId(req.params.id);
    res.json(logs || []);
  } catch (err) {
    console.error('[!] Error fetching repair logs:', err);
    res.status(500).json({ error: 'Failed to retrieve repair history' });
  }
});

app.post('/api/assets/:id/repairs', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  const asset_id = req.params.id;
  const { repair_start_date, issue_description, repair_cost, repaired_by } = req.body;

  if (!repair_start_date || !issue_description) {
    return res.status(400).json({ error: 'Repair start date and issue description are required' });
  }

  try {
    const result = await db.addAssetRepairLog({
      asset_id, repair_start_date, issue_description, repair_cost, repaired_by
    });
    res.status(201).json({ message: 'Repair log created and asset status updated', logId: result.id });
  } catch (err) {
    console.error('[!] Error logging repair:', err);
    res.status(500).json({ error: 'Failed to log asset repair' });
  }
});

app.put('/api/assets/repairs/:logId/complete', requireAuth, requireAssetManager, requireAssetAccess, async (req, res) => {
  const logId = req.params.logId;
  const { repair_end_date, repair_cost, status } = req.body;

  if (!repair_end_date) {
    return res.status(400).json({ error: 'Repair end date is required' });
  }

  try {
    await db.completeAssetRepair(logId, { repair_end_date, repair_cost, status });
    res.json({ message: 'Asset repair marked as completed' });
  } catch (err) {
    console.error('[!] Error completing repair:', err);
    res.status(500).json({ error: err.message || 'Failed to finalize repair log' });
  }
});

app.get('/api/my-assets', requireAuth, requireAssetAccess, async (req, res) => {
  const userId = req.session.user.id;
  try {
    const rows = await db.allAsync(
      `SELECT id, asset_tag, category, model, serial_number, cost, po_number, vendor, location FROM assets WHERE assigned_to = ? AND status = 'Assigned'`,
      [userId]
    );
    res.json(rows || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch your assigned assets' });
  }
});

// ================= REPORTING & EXPORT ROUTES =================

app.get('/api/admin/reports', requireAuth, requireAdminOrSuper, async (req, res) => {
  const { startDate, endDate, category } = req.query;
  let conditions = [];
  let params = [];

  if (startDate) { conditions.push('created_at >= ?'); params.push(`${startDate} 00:00:00`); }
  if (endDate) { conditions.push('created_at <= ?'); params.push(`${endDate} 23:59:59`); }
  if (category) { conditions.push('category = ?'); params.push(category); }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const reportQuery = `
    SELECT 
      COUNT(*) AS total_tickets,
      SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) AS open_tickets,
      SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress_tickets,
      SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_tickets,
      SUM(CASE WHEN status = 'Closed' THEN 1 ELSE 0 END) AS closed_tickets,
      SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) AS rejected_tickets,
      SUM(CASE WHEN sla_resolution_status = 'Met' THEN 1 ELSE 0 END) AS sla_met_count,
      SUM(CASE WHEN sla_resolution_status = 'Breached' THEN 1 ELSE 0 END) AS sla_breached_count,
      AVG(CASE WHEN resolved_at IS NOT NULL THEN (julianday(resolved_at) - julianday(created_at)) * 24 ELSE NULL END) AS avg_resolution_time_hours
    FROM tickets ${whereClause}
  `;

  try {
    const reportData = await db.getAsync(reportQuery, params);
    const totalEvaluated = (reportData.sla_met_count || 0) + (reportData.sla_breached_count || 0);
    const complianceRate = totalEvaluated > 0
      ? (((reportData.sla_met_count || 0) / totalEvaluated) * 100).toFixed(1)
      : '0.0';

    res.json({
      summary: {
        total: reportData.total_tickets || 0,
        open: reportData.open_tickets || 0,
        inProgress: reportData.in_progress_tickets || 0,
        resolved: reportData.resolved_tickets || 0,
        closed: reportData.closed_tickets || 0,
        rejected: reportData.rejected_tickets || 0
      },
      sla: {
        met: reportData.sla_met_count || 0,
        breached: reportData.sla_breached_count || 0,
        complianceRate: `${complianceRate}%`
      },
      performance: {
        avgResolutionTimeHours: reportData.avg_resolution_time_hours ? parseFloat(reportData.avg_resolution_time_hours.toFixed(2)) : 0
      }
    });
  } catch (err) {
    console.error('[!] Error generating report:', err);
    res.status(500).json({ error: 'Failed to generate helpdesk report' });
  }
});

app.get('/api/admin/reports/export', requireAuth, requireAdminOrSuper, async (req, res) => {
  const { startDate, endDate, category } = req.query;
  let conditions = [];
  let params = [];

  if (startDate) { conditions.push('t.created_at >= ?'); params.push(`${startDate} 00:00:00`); }
  if (endDate) { conditions.push('t.created_at <= ?'); params.push(`${endDate} 23:59:59`); }
  if (category) { conditions.push('t.category = ?'); params.push(category); }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const exportQuery = `
    SELECT 
      t.ticket_number, t.ticket_type, t.title, t.category, t.priority, t.status,
      u.name as requester_name, u.email as requester_email,
      t.sla_resolution_status, t.created_at, t.resolved_at, t.closed_at
    FROM tickets t LEFT JOIN users u ON t.requester_id = u.id
    ${whereClause} ORDER BY t.id DESC
  `;

  try {
    const rows = await db.allAsync(exportQuery, params);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=helpdesk_report_${Date.now()}.csv`);

    let csvString = 'Ticket Ref,Type,Title,Category,Priority,Status,Requester Name,Requester Email,SLA Status,Created At,Resolved At,Closed At\n';

    rows.forEach((r) => {
      csvString += [
        sanitizeCsvField(r.ticket_number), sanitizeCsvField(r.ticket_type), sanitizeCsvField(r.title),
        sanitizeCsvField(r.category), sanitizeCsvField(r.priority), sanitizeCsvField(r.status),
        sanitizeCsvField(r.requester_name), sanitizeCsvField(r.requester_email),
        sanitizeCsvField(r.sla_resolution_status), sanitizeCsvField(r.created_at),
        sanitizeCsvField(r.resolved_at), sanitizeCsvField(r.closed_at)
      ].join(',') + '\n';
    });

    res.send(csvString);
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate CSV export' });
  }
});

// ================= SCHEDULED CRON JOBS =================

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  cron.schedule('0 * * * *', async () => {
    console.log('[CRON] Running scheduled check for overdue SLA targets...');
    try {
      const nowIso = new Date().toISOString();
      const result = await db.runAsync(
        `UPDATE tickets 
         SET sla_resolution_status = 'Breached', updated_at = CURRENT_TIMESTAMP
         WHERE status IN ('Open', 'Approved', 'In Progress') 
           AND sla_target_resolution IS NOT NULL 
           AND datetime(sla_target_resolution) < datetime(?) 
           AND sla_resolution_status = 'Pending'`,
        [nowIso]
      );

      if (result.changes > 0) {
        console.log(`[CRON] Flagged ${result.changes} overdue tickets as SLA Breached.`);
      }
    } catch (err) {
      console.error('[CRON] Error checking SLA breaches:', err);
    }
  });

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;