/**
 * ThreatPulse — account & security email templates.
 *
 * Each builder returns { subject, html, text }. Everything user-controlled
 * (display names, addresses, IPs) is escaped; links are built by the server
 * from the configured public URL, never from request input.
 */

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Plain-text versions must not carry anything a mail client would render as a
// link or markup from a user-chosen display name.
function plain(v) {
  return String(v == null ? '' : v).replace(/[\r\n<>]/g, ' ').slice(0, 80);
}

function formatWhen(date = new Date()) {
  return date.toUTCString().replace('GMT', 'UTC');
}

const C = {
  bg: '#0b0c14', card: '#141625', border: '#262a40', text: '#e6e8f2', muted: '#9aa0b8',
  faint: '#6b7190', violet: '#7c5cff', cyan: '#22d3ee', red: '#ff4d6d', amber: '#ffb020',
};

function button(href, label) {
  return `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:24px auto;"><tr><td style="border-radius:10px;background:${C.violet};background-image:linear-gradient(135deg,${C.violet},${C.cyan});">
    <a href="${esc(href)}" style="display:inline-block;padding:13px 30px;font-size:15px;font-weight:700;color:#0b0c14;text-decoration:none;border-radius:10px;">${esc(label)}</a>
  </td></tr></table>`;
}

function layout({ preheader, heading, accent = C.cyan, bodyHtml, footerNote }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>${esc(heading)}</title></head>
<body style="margin:0;padding:0;background:${C.bg};font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:${C.text};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${esc(preheader)}</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:${C.bg};"><tr><td align="center" style="padding:32px 16px;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:520px;">
    <tr><td align="center" style="padding-bottom:20px;">
      <span style="font-size:22px;font-weight:800;letter-spacing:-0.3px;color:${C.text};">🛡️ Threat<span style="color:${C.cyan};">Pulse</span></span>
    </td></tr>
    <tr><td style="background:${C.card};border:1px solid ${C.border};border-top:3px solid ${accent};border-radius:14px;padding:28px 28px 24px;">
      <h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:${C.text};">${esc(heading)}</h1>
      ${bodyHtml}
    </td></tr>
    <tr><td align="center" style="padding:18px 8px 0;font-size:11.5px;line-height:1.6;color:${C.faint};">
      ${footerNote ? `${footerNote}<br>` : ''}This is an automated security message from ThreatPulse. Replies are not monitored.
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
}

const p = (html) => `<p style="margin:0 0 14px;font-size:14.5px;line-height:1.6;color:${C.muted};">${html}</p>`;

function detailsTable(rows) {
  return `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin:6px 0 16px;background:${C.bg};border:1px solid ${C.border};border-radius:10px;">
    ${rows.map(([k, v]) => `<tr><td style="padding:9px 14px;font-size:12.5px;color:${C.faint};width:38%;">${esc(k)}</td><td style="padding:9px 14px;font-size:12.5px;color:${C.text};word-break:break-all;">${esc(v)}</td></tr>`).join('')}
  </table>`;
}

// ---------------------------------------------------------------------------

function passwordReset({ name, link, expiresMinutes = 60, ip }) {
  const subject = 'Reset your ThreatPulse password';
  const html = layout({
    preheader: `Use this link within ${expiresMinutes} minutes to choose a new password.`,
    heading: 'Reset your password',
    accent: C.violet,
    bodyHtml:
      p(`Hi ${esc(name)},`) +
      p(`We received a request to reset the password for your ThreatPulse account. Click the button below to choose a new one. The link works <b style="color:${C.text};">once</b> and expires in <b style="color:${C.text};">${expiresMinutes} minutes</b>.`) +
      button(link, 'Reset password') +
      p(`If the button doesn't work, copy this link into your browser:<br><a href="${esc(link)}" style="color:${C.cyan};word-break:break-all;font-size:12.5px;">${esc(link)}</a>`) +
      (ip ? detailsTable([['Requested from IP', ip], ['Time', formatWhen()]]) : '') +
      p(`<b style="color:${C.text};">Didn't ask for this?</b> You can ignore this email — your password stays the same and nobody can use this link without access to your inbox.`),
  });
  const text = `Hi ${plain(name)},\n\nWe received a request to reset your ThreatPulse password.\nOpen this link within ${expiresMinutes} minutes to choose a new one (it works once):\n\n${link}\n\nIf you didn't ask for this, ignore this email - your password stays the same.\n`;
  return { subject, html, text };
}

function verificationCode({ name, type, code, expiresMinutes = 15 }) {
  const isEmail = type === 'email_change';
  const subject = isEmail ? `${code} is your ThreatPulse email verification code` : `${code} is your ThreatPulse password change code`;
  const what = isEmail ? 'confirm your new email address' : 'confirm your password change';
  const html = layout({
    preheader: `Your code is ${code}. It expires in ${expiresMinutes} minutes.`,
    heading: isEmail ? 'Confirm your new email' : 'Confirm your password change',
    accent: C.violet,
    bodyHtml:
      p(`Hi ${esc(name)},`) +
      p(`Enter this code in ThreatPulse to ${what}:`) +
      `<div style="margin:18px auto 20px;max-width:240px;text-align:center;background:${C.bg};border:1px solid ${C.violet};border-radius:12px;padding:16px 10px;font-family:'JetBrains Mono',Consolas,monospace;font-size:34px;font-weight:800;letter-spacing:8px;color:${C.cyan};">${esc(code)}</div>` +
      p(`The code expires in <b style="color:${C.text};">${expiresMinutes} minutes</b>. Never share it with anyone — ThreatPulse staff will never ask for it.`) +
      p(isEmail
        ? `If you didn't try to change your email, someone may know your password. Sign in and change it right away.`
        : `If you didn't try to change your password, someone may know it. Sign in and change it right away, or use "Forgot password".`),
  });
  const text = `Hi ${plain(name)},\n\nYour ThreatPulse code to ${what} is: ${code}\n\nIt expires in ${expiresMinutes} minutes. Never share it with anyone.\nIf you didn't request this, change your password right away.\n`;
  return { subject, html, text };
}

function passwordChanged({ name, method, ip, link }) {
  const how = { reset: 'with a password reset link', change: 'from your account settings', forced: 'during first sign-in', admin: 'by an administrator' }[method] || 'from your account';
  const subject = 'Your ThreatPulse password was changed';
  const html = layout({
    preheader: 'If this was you, no action is needed.',
    heading: 'Your password was changed',
    accent: C.amber,
    bodyHtml:
      p(`Hi ${esc(name)},`) +
      p(`The password for your ThreatPulse account was just changed ${esc(how)}. For your security, other signed-in sessions were signed out.`) +
      detailsTable([['Time', formatWhen()], ...(ip ? [['IP address', ip]] : [])]) +
      p(`<b style="color:${C.text};">If this was you</b>, no action is needed.`) +
      p(`<b style="color:${C.red};">If this wasn't you</b>, reset your password now with "Forgot password" on the sign-in page and tell your administrator.`) +
      (link ? button(`${link}/?forgot=1`, 'Secure my account') : ''),
  });
  const text = `Hi ${plain(name)},\n\nYour ThreatPulse password was changed ${how} at ${formatWhen()}${ip ? ` from ${ip}` : ''}.\nIf this was you, no action is needed.\nIf it wasn't, use "Forgot password" on the sign-in page${link ? ` (${link}/?forgot=1)` : ''} right away and tell your administrator.\n`;
  return { subject, html, text };
}

function emailChanged({ name, oldEmail, newEmail, toOld, link }) {
  const subject = toOld ? 'The email on your ThreatPulse account was changed' : 'Your ThreatPulse email address is confirmed';
  const html = layout({
    preheader: toOld ? `Your account now uses a different email address.` : 'You will now receive account emails here.',
    heading: toOld ? 'Your account email was changed' : 'Email address confirmed',
    accent: toOld ? C.amber : C.cyan,
    bodyHtml:
      p(`Hi ${esc(name)},`) +
      p(toOld
        ? `The email address on your ThreatPulse account was changed. Password resets and security notices now go to the new address.`
        : `This address is now the email for your ThreatPulse account. Password resets and security notices will be sent here.`) +
      detailsTable([['Previous email', oldEmail || '—'], ['New email', newEmail], ['Time', formatWhen()]]) +
      (toOld ? p(`<b style="color:${C.red};">If this wasn't you</b>, your account may be compromised. Contact your ThreatPulse administrator immediately.`) : '') +
      (link && !toOld ? button(link, 'Open ThreatPulse') : ''),
  });
  const text = toOld
    ? `Hi ${plain(name)},\n\nThe email on your ThreatPulse account was changed from ${oldEmail} to ${newEmail} at ${formatWhen()}.\nIf this wasn't you, contact your administrator immediately.\n`
    : `Hi ${plain(name)},\n\n${newEmail} is now the email for your ThreatPulse account. Password resets and security notices will be sent here.\n`;
  return { subject, html, text };
}

function welcome({ name, username, link }) {
  const subject = 'Welcome to ThreatPulse';
  const html = layout({
    preheader: 'Your account is ready.',
    heading: `Welcome aboard, ${name}`,
    bodyHtml:
      p(`Your ThreatPulse account <b style="color:${C.text};">${esc(username)}</b> is ready. Add the feeds you care about, set your alert channels, and ThreatPulse will keep watch for you.`) +
      (link ? button(link, 'Open your dashboard') : '') +
      p(`Forgot your password later? Use "Forgot password" on the sign-in page and we'll send a reset link to this address.`),
  });
  const text = `Welcome to ThreatPulse, ${plain(name)}!\n\nYour account "${plain(username)}" is ready.${link ? `\nOpen your dashboard: ${link}` : ''}\n\nIf you forget your password, use "Forgot password" on the sign-in page and we'll email you a reset link.\n`;
  return { subject, html, text };
}

module.exports = { passwordReset, verificationCode, passwordChanged, emailChanged, welcome, esc };
