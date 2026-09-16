const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const router = express.Router();
const db = require('./database');
const { requireAuth } = require('./auth-guard');

/**
 * Universal Async Helpers: Wraps standard sqlite3 callback functions in Promises
 * so async/await works properly without throwing unhandled execution errors.
 */
function execRun(sql, params = []) {
  if (typeof db.runAsync === 'function') {
    return db.runAsync(sql, params);
  }
  return new Promise((resolve, reject) => {
    if (typeof db.run === 'function') {
      db.run(sql, params, function (err) {
        if (err) return reject(err);
        resolve(this);
      });
    } else if (typeof db.query === 'function') {
      db.query(sql, params).then(resolve).catch(reject);
    } else {
      reject(new Error('No suitable database execution method found.'));
    }
  });
}

function execAll(sql, params = []) {
  if (typeof db.allAsync === 'function') {
    return db.allAsync(sql, params);
  }
  return new Promise((resolve, reject) => {
    if (typeof db.all === 'function') {
      db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    } else if (typeof db.query === 'function') {
      db.query(sql, params).then(resolve).catch(reject);
    } else {
      reject(new Error('No suitable database query method found.'));
    }
  });
}

/**
 * Universal Helper: Fetches and normalizes user security questions & answer hashes.
 */
async function getUserSecurityData(userId) {
  try {
    let raw = null;
    if (typeof db.getSecurityQuestionsByUserId === 'function') {
      raw = await db.getSecurityQuestionsByUserId(userId);
    } else if (typeof db.getUserSecurityQuestions === 'function') {
      raw = await db.getUserSecurityQuestions(userId);
    } else {
      const rows = await execAll(
        'SELECT question_1, answer_1_hash, question_2, answer_2_hash FROM user_security_questions WHERE user_id = ?',
        [userId]
      );
      raw = rows ? rows[0] : null;
    }

    if (!raw) return null;

    if (Array.isArray(raw) && raw.length >= 2) {
      return {
        q1: raw[0].question || raw[0].question_1,
        a1Hash: raw[0].answerHash || raw[0].answer_1_hash || raw[0].answer_hash,
        q2: raw[1].question || raw[1].question_2,
        a2Hash: raw[1].answerHash || raw[1].answer_2_hash || raw[1].answer_hash
      };
    }

    if (typeof raw === 'object') {
      const q1 = raw.question_1 || raw.q1 || (raw[0] && raw[0].question);
      const q2 = raw.question_2 || raw.q2 || (raw[1] && raw[1].question);
      const a1Hash = raw.answer_1_hash || raw.answer1_hash || raw.a1Hash || (raw[0] && (raw[0].answerHash || raw[0].answer_hash));
      const a2Hash = raw.answer_2_hash || raw.answer2_hash || raw.a2Hash || (raw[1] && (raw[1].answerHash || raw[1].answer_hash));

      if (q1 && q2) {
        return { q1, a1Hash, q2, a2Hash };
      }
    }

    return null;
  } catch (err) {
    console.error('Error fetching security data:', err);
    return null;
  }
}

/**
 * Helper to check if a user has configured security questions
 */
async function checkHasSecurityQuestions(userId) {
  const data = await getUserSecurityData(userId);
  return Boolean(data && data.q1 && data.q2);
}

/**
 * GET /api/auth/me
 */
router.get('/me', requireAuth, async (req, res) => {
  try {
    const sessionUser = req.user || req.session?.user?.user || req.session?.user;
    
    const user = await db.findUserByEmail(sessionUser.email);
    if (!user) {
      return res.status(401).json({ error: 'User account no longer exists.' });
    }

    const mustChangePassword = user.role !== 'super_admin' && Boolean(user.must_change_password);
    const hasSecurityQuestions = await checkHasSecurityQuestions(user.id);

    const safeUser = {
      id: user.id,
      email: user.email,
      role: user.role,
      access_helpdesk: user.access_helpdesk,
      access_assets: user.access_assets,
      name: user.name || user.full_name || undefined,
      subsidiary: user.subsidiary || null,
      department: user.department || null,
      must_change_password: mustChangePassword,
      has_security_questions: hasSecurityQuestions
    };

    return res.status(200).json(safeUser);
  } catch (error) {
    console.error('Auth /me Error:', error);
    return res.status(500).json({ error: 'Failed to retrieve current user context.' });
  }
});

/**
 * POST /api/auth/login
 */
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash || user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const mustChangePassword = user.role !== 'super_admin' && Boolean(user.must_change_password);
    const hasSecurityQuestions = await checkHasSecurityQuestions(user.id);

    const sessionData = {
      id: user.id,
      email: user.email,
      role: user.role,
      access_helpdesk: user.access_helpdesk,
      access_assets: user.access_assets,
      must_change_password: mustChangePassword,
      has_security_questions: hasSecurityQuestions
    };

    req.session.user = sessionData;

    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Failed to initialize user session.' });
      }

      return res.status(200).json({
        message: 'Login successful.',
        user: sessionData,
        mustChangePassword: mustChangePassword,
        hasSecurityQuestions: hasSecurityQuestions
      });
    });
  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({ error: 'Server error during login.' });
  }
});

/**
 * POST /api/auth/change-password
 */
router.post('/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body;
  const sessionUser = req.user || req.session?.user?.user || req.session?.user;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    if (typeof db.updateUserPassword === 'function') {
      await db.updateUserPassword(sessionUser.id, hashedPassword);
    } else {
      await execRun('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, sessionUser.id]);
    }

    return res.status(200).json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Change Password Error:', error);
    return res.status(500).json({ error: 'Failed to update password.' });
  }
});

/**
 * POST /api/auth/setup-security-questions
 */
router.post('/setup-security-questions', requireAuth, async (req, res) => {
  const { question1, answer1, question2, answer2 } = req.body;
  const sessionUser = req.user || req.session?.user?.user || req.session?.user;

  if (!question1 || !answer1 || !question2 || !answer2) {
    return res.status(400).json({ error: 'All security questions and answers are required.' });
  }

  try {
    const hashedA1 = await bcrypt.hash(answer1.trim().toLowerCase(), 10);
    const hashedA2 = await bcrypt.hash(answer2.trim().toLowerCase(), 10);

    if (typeof db.saveUserSecurityQuestions === 'function') {
      await db.saveUserSecurityQuestions(sessionUser.id, [
        { question: question1, answerHash: hashedA1 },
        { question: question2, answerHash: hashedA2 }
      ]);
    } else if (typeof db.setSecurityQuestions === 'function') {
      await db.setSecurityQuestions(sessionUser.id, question1, hashedA1, question2, hashedA2);
    } else {
      await execRun(
        `INSERT INTO user_security_questions (user_id, question_1, answer_1_hash, question_2, answer_2_hash)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           question_1 = excluded.question_1,
           answer_1_hash = excluded.answer_1_hash,
           question_2 = excluded.question_2,
           answer_2_hash = excluded.answer_2_hash`,
        [sessionUser.id, question1, hashedA1, question2, hashedA2]
      );
    }

    if (typeof db.clearMustChangePasswordFlag === 'function') {
      await db.clearMustChangePasswordFlag(sessionUser.id);
    } else {
      await execRun('UPDATE users SET must_change_password = 0 WHERE id = ?', [sessionUser.id]);
    }

    if (req.session && req.session.user) {
      req.session.user.must_change_password = false;
      req.session.user.has_security_questions = true;
    }

    return res.status(200).json({ message: 'Security questions saved successfully.' });
  } catch (error) {
    console.error('Setup Security Questions Error:', error);
    return res.status(500).json({ error: 'Failed to save security questions.' });
  }
});

/**
 * GET /api/auth/security-questions?email=...
 */
router.get('/security-questions', async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    if (!user) {
      return res.status(404).json({ error: 'No account found with that email address.' });
    }

    const secData = await getUserSecurityData(user.id);

    if (!secData || !secData.q1 || !secData.q2) {
      return res.status(404).json({ error: 'Security questions have not been configured for this account.' });
    }

    return res.status(200).json({
      question_1: secData.q1,
      question_2: secData.q2
    });
  } catch (error) {
    console.error('Fetch Security Questions Error:', error);
    return res.status(500).json({ error: 'Failed to retrieve security questions.' });
  }
});

/**
 * POST /api/auth/reset-password-security
 */
router.post('/reset-password-security', async (req, res) => {
  const { email, answer1, answer2, newPassword } = req.body;

  if (!email || !answer1 || !answer2 || !newPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    if (!user) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    let a1Hash = null;
    let a2Hash = null;

    const secData = await getUserSecurityData(user.id);
    if (secData) {
      a1Hash = secData.a1Hash;
      a2Hash = secData.a2Hash;
    }

    if (!a1Hash || !a2Hash) {
      const rows = await execAll(
        'SELECT answer_1_hash, answer_2_hash FROM user_security_questions WHERE user_id = ?',
        [user.id]
      );
      if (rows && rows.length > 0) {
        a1Hash = rows[0].answer_1_hash;
        a2Hash = rows[0].answer_2_hash;
      }
    }

    if (!a1Hash || !a2Hash) {
      return res.status(400).json({ error: 'Security questions have not been set up for this account.' });
    }

    const match1 = await bcrypt.compare(answer1.trim().toLowerCase(), a1Hash);
    const match2 = await bcrypt.compare(answer2.trim().toLowerCase(), a2Hash);

    if (!match1 || !match2) {
      return res.status(400).json({ error: 'Incorrect answers to security questions.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    if (typeof db.updateUserPassword === 'function') {
      await db.updateUserPassword(user.id, hashedPassword);
    } else {
      await execRun('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?', [hashedPassword, user.id]);
    }

    return res.status(200).json({ message: 'Password reset successfully.' });
  } catch (error) {
    console.error('Reset Password via Security Error:', error);
    return res.status(500).json({ error: 'Server error resetting password.' });
  }
});

/**
 * POST /api/auth/first-time-setup
 */
router.post('/first-time-setup', async (req, res) => {
  const { userId, new_password, question_1, answer_1, question_2, answer_2 } = req.body;

  if (!userId || !new_password || !question_1 || !answer_1 || !question_2 || !answer_2) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(new_password, 10);
    const hashedA1 = await bcrypt.hash(answer_1.trim().toLowerCase(), 10);
    const hashedA2 = await bcrypt.hash(answer_2.trim().toLowerCase(), 10);

    if (typeof db.updateUserPassword === 'function') {
      await db.updateUserPassword(userId, hashedPassword);
    } else {
      await execRun('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?', [hashedPassword, userId]);
    }

    if (typeof db.saveUserSecurityQuestions === 'function') {
      await db.saveUserSecurityQuestions(userId, [
        { question: question_1, answerHash: hashedA1 },
        { question: question_2, answerHash: hashedA2 }
      ]);
    } else {
      await execRun(
        `INSERT INTO user_security_questions (user_id, question_1, answer_1_hash, question_2, answer_2_hash)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           question_1 = excluded.question_1,
           answer_1_hash = excluded.answer_1_hash,
           question_2 = excluded.question_2,
           answer_2_hash = excluded.answer_2_hash`,
        [userId, question_1, hashedA1, question_2, hashedA2]
      );
    }

    return res.status(200).json({ message: 'First-time setup completed successfully.' });
  } catch (error) {
    console.error('First Time Setup Error:', error);
    return res.status(500).json({ error: 'Failed to complete setup.' });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
        return res.status(500).json({ error: 'Could not log out.' });
      }
      
      res.clearCookie('connect.sid', { path: '/' });
      return res.status(200).json({ message: 'Logged out successfully.' });
    });
  } else {
    res.clearCookie('connect.sid', { path: '/' });
    return res.status(200).json({ message: 'Logged out successfully.' });
  }
});

/**
 * POST /api/auth/forgot-password
 */
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    
    if (!user) {
      return res.status(200).json({ 
        message: 'If an account with that email exists, a reset token has been generated.' 
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000);

    await db.updateUserResetToken(user.id, resetTokenHash, resetTokenExpires);

    const secData = await getUserSecurityData(user.id);
    const questions = secData ? [
      { id: 1, question: secData.q1 },
      { id: 2, question: secData.q2 }
    ] : [];

    return res.status(200).json({
      message: 'Reset token generated successfully.',
      token: resetToken,
      questions
    });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    return res.status(500).json({ error: 'Server error processing password reset.' });
  }
});

/**
 * GET /api/auth/verify-reset-token/:token
 */
router.get('/verify-reset-token/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await db.findUserByResetToken(tokenHash);

    if (!user || new Date(user.reset_token_expires) < new Date()) {
      return res.status(400).json({ valid: false, error: 'Invalid or expired token.' });
    }

    const secData = await getUserSecurityData(user.id);
    const questions = secData ? [
      { id: 1, question: secData.q1 },
      { id: 2, question: secData.q2 }
    ] : [];

    return res.status(200).json({ 
      valid: true,
      questions
    });
  } catch (error) {
    return res.status(500).json({ valid: false, error: 'Failed to verify token.' });
  }
});

/**
 * POST /api/auth/reset-password
 */
router.post('/reset-password', async (req, res) => {
  const { token, newPassword, answers } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await db.findUserByResetToken(tokenHash);

    if (!user || new Date(user.reset_token_expires) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired password reset token.' });
    }

    const secData = await getUserSecurityData(user.id);

    if (secData && secData.a1Hash && secData.a2Hash) {
      if (!answers || !Array.isArray(answers) || answers.length < 2) {
        return res.status(400).json({ error: 'Security question answers are required to reset password.' });
      }

      const match1 = await bcrypt.compare(answers[0].answer.trim().toLowerCase(), secData.a1Hash);
      const match2 = await bcrypt.compare(answers[1].answer.trim().toLowerCase(), secData.a2Hash);

      if (!match1 || !match2) {
        return res.status(400).json({ error: 'Incorrect answers to security questions.' });
      }
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    if (typeof db.updateUserPasswordAndClearToken === 'function') {
      await db.updateUserPasswordAndClearToken(user.id, hashedPassword);
    } else {
      await execRun(
        'UPDATE users SET password = ?, reset_token_hash = NULL, reset_token_expires = NULL, must_change_password = 0 WHERE id = ?',
        [hashedPassword, user.id]
      );
    }

    return res.status(200).json({ message: 'Password updated successfully.' });

  } catch (error) {
    console.error('Reset Password Error:', error);
    return res.status(500).json({ error: 'Server error resetting password.' });
  }
});

module.exports = router;