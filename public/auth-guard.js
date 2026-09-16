/**
 * Universal Auth Guard & Access Control Utilities
 * Supports Express Node.js Server Middleware & Browser Client Guards.
 */

// ============================================================================
// 1. HELPER FUNCTIONS
// ============================================================================

/**
 * Extracts and normalizes the user object from Express request context.
 * Supports standard Express session structure, double-wrapped user objects, and req.user (JWTs).
 */
function extractUser(req) {
  if (!req) return null;
  const user = req.user || req.session?.user?.user || req.session?.user;
  return (user && typeof user === 'object') ? user : null;
}

/**
 * Normalizes boolean flags from DB (handles 1, "1", true, "true").
 */
function isTruthy(val) {
  return val === true || val === 1 || val === '1' || String(val).toLowerCase() === 'true';
}

/**
 * Helper to check standard admin roles.
 */
function isAdminRole(role) {
  const normalized = String(role || '').trim().toLowerCase();
  return ['admin', 'super_admin', 'superadmin'].includes(normalized);
}

/**
 * Determines if a user requires a mandatory password reset or initial security setup.
 * STRICT EXEMPTION: super_admin accounts are NEVER forced to reset.
 */
function needsPasswordReset(user) {
  if (!user) return false;
  const role = String(user.role || '').trim().toLowerCase();
  if (role === 'super_admin' || role === 'superadmin') {
    return false;
  }
  return isTruthy(user.must_change_password || user.mustChangePassword);
}

/**
 * Checks if a user needs first-time security setup (Password reset or missing security questions).
 */
function needsForcedSetup(user) {
  if (!user) return false;
  const role = String(user.role || '').trim().toLowerCase();
  if (role === 'super_admin' || role === 'superadmin') {
    return false;
  }
  return needsPasswordReset(user) || user.has_security_questions === false;
}

// ============================================================================
// 2. EXPRESS SERVER-SIDE MIDDLEWARE
// ============================================================================

/**
 * Ensures the request is authenticated via session or populated request user.
 * Blocks access if a mandatory password reset is pending.
 */
function requireAuth(req, res, next) {
  const user = extractUser(req);
  if (!user || (!user.id && !user._id)) {
    return res.status(401).json({ error: 'Unauthorized. Active session required.' });
  }

  // Enforce password reset check (Excludes password change and security question endpoints)
  if (needsPasswordReset(user) && !req.path.includes('/change-password') && !req.path.includes('/setup-security-questions')) {
    return res.status(403).json({ 
      error: 'Password reset required.', 
      mustChangePassword: true 
    });
  }

  next();
}

/**
 * Restricts access to Admin roles.
 */
function requireAdmin(req, res, next) {
  const user = extractUser(req);
  if (!user || !isAdminRole(user.role)) {
    return res.status(403).json({ error: 'Forbidden. Administrator privileges required.' });
  }

  if (needsPasswordReset(user) && !req.path.includes('/change-password') && !req.path.includes('/setup-security-questions')) {
    return res.status(403).json({ 
      error: 'Password reset required.', 
      mustChangePassword: true 
    });
  }

  next();
}

/**
 * Restricts access specifically to Admin or Super Admin roles.
 */
function requireAdminOrSuper(req, res, next) {
  return requireAdmin(req, res, next);
}

/**
 * Restricts access to Managers or higher roles.
 */
function requireManager(req, res, next) {
  const user = extractUser(req);
  const role = String(user?.role || '').trim().toLowerCase();
  if (!user || (!['manager'].includes(role) && !isAdminRole(role))) {
    return res.status(403).json({ error: 'Forbidden. Manager privileges required.' });
  }

  if (needsPasswordReset(user) && !req.path.includes('/change-password') && !req.path.includes('/setup-security-questions')) {
    return res.status(403).json({ 
      error: 'Password reset required.', 
      mustChangePassword: true 
    });
  }

  next();
}

/**
 * Restricts access to Asset Managers or Admins.
 */
function requireAssetManager(req, res, next) {
  const user = extractUser(req);
  const role = String(user?.role || '').trim().toLowerCase();
  if (!user || (!['asset_manager'].includes(role) && !isAdminRole(role))) {
    return res.status(403).json({ error: 'Forbidden. Asset management privileges required.' });
  }

  if (needsPasswordReset(user) && !req.path.includes('/change-password') && !req.path.includes('/setup-security-questions')) {
    return res.status(403).json({ 
      error: 'Password reset required.', 
      mustChangePassword: true 
    });
  }

  next();
}

/**
 * Checks module-level access flag for Helpdesk.
 */
function requireHelpdeskAccess(req, res, next) {
  const user = extractUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized. Active session required.' });
  }

  if (needsPasswordReset(user) && !req.path.includes('/change-password') && !req.path.includes('/setup-security-questions')) {
    return res.status(403).json({ 
      error: 'Password reset required.', 
      mustChangePassword: true 
    });
  }

  if (isAdminRole(user.role) || isTruthy(user.access_helpdesk)) {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden. Helpdesk module access disabled.' });
}

/**
 * Checks module-level access flag for Assets.
 */
function requireAssetAccess(req, res, next) {
  const user = extractUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized. Active session required.' });
  }

  if (needsPasswordReset(user) && !req.path.includes('/change-password') && !req.path.includes('/setup-security-questions')) {
    return res.status(403).json({ 
      error: 'Password reset required.', 
      mustChangePassword: true 
    });
  }

  if (isAdminRole(user.role) || isTruthy(user.access_assets)) {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden. Asset management module access disabled.' });
}

// ============================================================================
// 3. CLIENT-SIDE BROWSER UTILITIES & DYNAMIC MODAL INJECTION
// ============================================================================

/**
 * Dynamically renders and displays the forced password reset & security question modal.
 */
function renderForcedSetupModal(showPasswordFields = true) {
  if (document.getElementById('forcedSetupModal')) return;

  const passwordSectionHTML = showPasswordFields ? `
    <div class="mb-3">
      <label class="form-label small fw-bold mb-1">New Password</label>
      <input type="password" id="guardNewPassword" class="form-control form-control-sm" required autocomplete="new-password">
    </div>
  ` : '';

  const modalHTML = `
    <div class="modal fade" id="forcedSetupModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-hidden="true" style="z-index: 1090;">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-0 shadow-lg">
          <div class="modal-header bg-primary text-white">
            <h5 class="modal-title fw-bold fs-6">Account Setup Required</h5>
          </div>
          <div class="modal-body p-4">
            <p class="text-muted small mb-3">You must complete your account security configuration before continuing.</p>
            
            <div id="setupAlert" class="alert alert-danger d-none small py-2"></div>

            <form id="forcedSetupForm" onsubmit="handleGuardSetupSubmit(event, ${showPasswordFields})">
              ${passwordSectionHTML}

              <!-- Security Questions -->
              <div class="border-top pt-3 mt-3">
                <h6 class="fw-bold small text-dark mb-2">Set Recovery Security Questions</h6>
                
                <div class="mb-2">
                  <label class="form-label text-muted mb-1" style="font-size: 0.75rem;">Question 1</label>
                  <select id="guardQ1" class="form-select form-select-sm" required>
                    <option value="">Select a question...</option>
                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                    <option value="What was the make of your first car?">What was the make of your first car?</option>
                    <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
                  </select>
                  <input type="text" id="guardA1" class="form-control form-control-sm mt-1" placeholder="Answer 1" required>
                </div>

                <div class="mb-3">
                  <label class="form-label text-muted mb-1" style="font-size: 0.75rem;">Question 2</label>
                  <select id="guardQ2" class="form-select form-select-sm" required>
                    <option value="">Select a question...</option>
                    <option value="What elementary school did you attend?">What elementary school did you attend?</option>
                    <option value="In what city were you born?">In what city were you born?</option>
                    <option value="Who was your favorite teacher?">Who was your favorite teacher?</option>
                  </select>
                  <input type="text" id="guardA2" class="form-control form-control-sm mt-1" placeholder="Answer 2" required>
                </div>
              </div>

              <button type="submit" id="btnSubmitGuardSetup" class="btn btn-primary btn-sm w-100 fw-bold mt-2 py-2">
                Save & Continue
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>`;

  document.body.insertAdjacentHTML('beforeend', modalHTML);

  if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
    const modalEl = document.getElementById('forcedSetupModal');
    const modal = new bootstrap.Modal(modalEl, { backdrop: 'static', keyboard: false });
    modal.show();
  }
}

/**
 * Submission Handler for the Injected Guard Setup Modal
 */
if (typeof window !== 'undefined') {
  window.handleGuardSetupSubmit = async function (e, requiresPassword = true) {
    e.preventDefault();
    const alertBox = document.getElementById('setupAlert');
    const submitBtn = document.getElementById('btnSubmitGuardSetup');

    alertBox.classList.add('d-none');

    const q1 = document.getElementById('guardQ1').value;
    const q2 = document.getElementById('guardQ2').value;

    if (q1 === q2) {
      alertBox.innerText = 'Please select two different security questions.';
      alertBox.classList.remove('d-none');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerText = 'Updating...';

    try {
      // 1. Submit password change if required
      if (requiresPassword) {
        const newPassword = document.getElementById('guardNewPassword').value;
        const pwdRes = await authFetch('/api/auth/change-password', {
          method: 'POST',
          body: JSON.stringify({ newPassword })
        });

        if (!pwdRes || !pwdRes.ok) {
          const pwdData = pwdRes ? await pwdRes.json() : {};
          throw new Error(pwdData.error || 'Failed to update password.');
        }
      }

      // 2. Submit security questions setup
      const secRes = await authFetch('/api/auth/setup-security-questions', {
        method: 'POST',
        body: JSON.stringify({
          question1: q1,
          answer1: document.getElementById('guardA1').value,
          question2: q2,
          answer2: document.getElementById('guardA2').value
        })
      });

      if (!secRes || !secRes.ok) {
        const secData = secRes ? await secRes.json() : {};
        throw new Error(secData.error || 'Failed to save security questions.');
      }

      // Refresh window to load standard authenticated state
      window.location.reload();
    } catch (err) {
      alertBox.innerText = err.message;
      alertBox.classList.remove('d-none');
      submitBtn.disabled = false;
      submitBtn.innerText = 'Save & Continue';
    }
  };
}

async function protectPage(allowedRoles = []) {
  try {
    const headers = { 'Accept': 'application/json' };
    const token = typeof localStorage !== 'undefined' ? (localStorage.getItem('token') || localStorage.getItem('jwt')) : null;
    
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch('/api/auth/me', {
      method: 'GET',
      headers: headers,
      credentials: 'same-origin'
    });

    if (response.status === 401 || response.status === 403) {
      throw new Error('Unauthorized or expired session');
    }

    if (!response.ok) {
      throw new Error(`Authentication check failed: ${response.status}`);
    }

    const user = await response.json();

    // Browser-side check: Prompt setup modal on current page if reset or questions setup is pending
    if (needsForcedSetup(user)) {
      const needsPassword = needsPasswordReset(user);
      renderForcedSetupModal(needsPassword);
      return user;
    }

    const userRole = String(user.role || '').toLowerCase();
    const normalizedAllowed = allowedRoles.map(r => String(r).toLowerCase());

    if (normalizedAllowed.length > 0 && !normalizedAllowed.includes(userRole)) {
      window.location.href = '/login.html';
      return null;
    }

    return user;
  } catch (error) {
    console.warn('Access denied. Redirecting to login:', error.message);
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('token');
      localStorage.removeItem('jwt');
    }
    const currentPath = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login.html?redirect=${currentPath}`;
    return null;
  }
}

async function authFetch(url, options = {}) {
  try {
    const token = typeof localStorage !== 'undefined' ? (localStorage.getItem('token') || localStorage.getItem('jwt')) : null;
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });

    if (response.status === 401) {
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem('token');
        localStorage.removeItem('jwt');
      }
      const currentPath = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.href = `/login.html?redirect=${currentPath}`;
      return null;
    }

    return response;
  } catch (err) {
    console.error('Network or Request Error during authFetch:', err);
    throw err;
  }
}

// Global Browser Export
if (typeof window !== 'undefined') {
  window.protectPage = protectPage;
  window.authFetch = authFetch;
}

// CommonJS Node.js Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    requireAuth,
    requireAdmin,
    requireAdminOrSuper,
    requireManager,
    requireAssetManager,
    requireHelpdeskAccess,
    requireAssetAccess,
    protectPage,
    authFetch
  };
}