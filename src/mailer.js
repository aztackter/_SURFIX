var nodemailer = require("nodemailer");

var HOST = (process.env.PUBLIC_URL || "http://localhost:3000").replace(/\/$/, "");

var _transporter = null;
function getTransporter() {
  if (_transporter) return _transporter;
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    throw new Error("SMTP_HOST, SMTP_USER, and SMTP_PASS must be set to send emails");
  }
  _transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
  return _transporter;
}

var FROM = process.env.SMTP_FROM || "SURFIX <noreply@surfix.app>";

async function sendVerificationEmail(email, username, token) {
  var link = HOST + "/api/user/verify-email?token=" + token;
  await getTransporter().sendMail({
    from: FROM,
    to: email,
    subject: "Verify your SURFIX account",
    html: "<div style='font-family:sans-serif;max-width:480px;margin:0 auto;background:#01010c;color:#f2f2ff;padding:2rem;border-radius:16px;border:1px solid rgba(124,58,237,0.3)'>" +
      "<h1 style='color:#c084fc;font-size:1.8rem;margin:0 0 0.5rem'>SURFIX</h1>" +
      "<p style='color:rgba(255,255,255,0.6);margin:0 0 1.5rem'>Lua Protection and Licensing</p>" +
      "<h2 style='font-size:1.2rem;margin:0 0 1rem'>Hi " + username + ", verify your email</h2>" +
      "<p style='color:rgba(255,255,255,0.5);line-height:1.6;margin:0 0 1.5rem'>Click the button below to verify your email and activate your account. This link expires in 24 hours.</p>" +
      "<a href='" + link + "' style='display:inline-block;background:linear-gradient(135deg,#7c3aed,#ec4899);color:#fff;text-decoration:none;padding:12px 28px;border-radius:40px;font-weight:700'>Verify Email</a>" +
      "<p style='color:rgba(255,255,255,0.25);font-size:0.75rem;margin-top:2rem'>If you did not create a SURFIX account, you can safely ignore this email.</p>" +
      "</div>"
  });
}

async function sendPasswordResetEmail(email, username, token) {
  var link = HOST + "/reset-password?token=" + token;
  await getTransporter().sendMail({
    from: FROM,
    to: email,
    subject: "Reset your SURFIX password",
    html: "<div style='font-family:sans-serif;max-width:480px;margin:0 auto;background:#01010c;color:#f2f2ff;padding:2rem;border-radius:16px;border:1px solid rgba(124,58,237,0.3)'>" +
      "<h1 style='color:#c084fc;font-size:1.8rem;margin:0 0 0.5rem'>SURFIX</h1>" +
      "<h2 style='font-size:1.2rem;margin:0 0 1rem'>Password reset request</h2>" +
      "<p style='color:rgba(255,255,255,0.5);line-height:1.6;margin:0 0 1.5rem'>Hi " + username + ", someone requested a password reset. This link is valid for 1 hour.</p>" +
      "<a href='" + link + "' style='display:inline-block;background:linear-gradient(135deg,#7c3aed,#ec4899);color:#fff;text-decoration:none;padding:12px 28px;border-radius:40px;font-weight:700'>Reset Password</a>" +
      "<p style='color:rgba(255,255,255,0.25);font-size:0.75rem;margin-top:2rem'>If you did not request this, ignore this email - your password will not change.</p>" +
      "</div>"
  });
}

module.exports = { sendVerificationEmail: sendVerificationEmail, sendPasswordResetEmail: sendPasswordResetEmail };
