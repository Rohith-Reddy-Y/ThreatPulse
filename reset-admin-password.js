/**
 * ThreatPulse — Admin Password Reset Utility
 * Run on the EC2 instance:  node reset-admin-password.js
 *
 * Or set ADMIN_INITIAL_PASSWORD in your .env and the server will
 * apply it when the admin account is locked.
 *
 * Note: failed-login lockouts are kept in the running server's memory (per
 * account + client IP), not in the database — restarting the server clears
 * them. The legacy locked_until / failed_login_attempts columns are still
 * reset here for databases written by older versions.
 */
const auth = require('./src/auth');
const db = require('./src/database');

const newPassword = process.argv[2] || process.env.ADMIN_INITIAL_PASSWORD;

async function main() {
  if (!newPassword) {
    // No password provided — just unlock the admin and show current state
    const d = db.getDb();
    const admin = d.prepare("SELECT * FROM users WHERE role = 'admin'").get();
    if (admin) {
      d.prepare("UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE role = 'admin'").run();
      console.log('Admin account UNLOCKED (legacy DB lock cleared; restart the server to clear in-memory login lockouts).');
      console.log(`  Username: admin`);
      console.log(`  Must change password: ${admin.must_change_password ? 'YES' : 'NO'}`);
      console.log('');
      console.log('To set a new password:');
      console.log('  node reset-admin-password.js "YourNewPassword123"');
      console.log('  OR set ADMIN_INITIAL_PASSWORD=YourNewPassword123 in .env and restart');
    } else {
      console.log('No admin user found. The server will create one on next start.');
    }
  } else {
    // Set a new password
    const pwCheck = auth.validatePasswordStrength(newPassword);
    if (!pwCheck.valid) {
      console.error('Password too weak:', pwCheck.error);
      console.error('Must be 8+ chars with uppercase, lowercase, and number.');
      process.exit(1);
    }

    const d = db.getDb();
    const salt = auth.generateSalt();
    const hash = await auth.hashPassword(newPassword, salt);

    let admin = d.prepare("SELECT id FROM users WHERE role = 'admin'").get();
    if (admin) {
      d.prepare("UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0, locked_until = NULL, failed_login_attempts = 0 WHERE id = ?").run(hash, salt, admin.id);
      console.log(`Admin password RESET to: ${newPassword}`);
      console.log('  Username: admin');
    } else {
      d.prepare("INSERT INTO users (username, display_name, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)").run('admin', 'Administrator', hash, salt, 'admin');
      console.log('Admin user CREATED.');
      console.log(`  Username: admin`);
      console.log(`  Password: ${newPassword}`);
    }
  }
}

// auth.js schedules housekeeping intervals that would keep this one-shot script alive
main().then(() => process.exit(0)).catch((err) => {
  console.error('Failed:', err && err.message ? err.message : err);
  process.exit(1);
});
