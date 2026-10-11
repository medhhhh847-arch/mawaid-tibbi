// موعد طبي — REST API (Express + PostgreSQL)
// Run:  npm install && DATABASE_URL=... JWT_SECRET=... node server.js

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const B = require('./booking');

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET (32+ chars) is required');

const app = express();
app.set('trust proxy', 1);   // behind the hosting provider's proxy: use the real client IP for rate limits
app.use(helmet());
app.use(express.json({ limit: '50kb' }));

// CORS: only the origins listed in ALLOWED_ORIGINS (comma-separated), e.g. https://admin.example.com
const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10 });

// small helper so async errors reach the error handler
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);

// ───────────── Auth: phone + OTP ─────────────
// OTPs are kept in memory for now. Replace sendSms() with a real SMS provider
// and move the codes to Redis/DB before running more than one server instance.
const otps = new Map(); // phone -> { hash, expires, tries }
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function sendSms(phone, text) {
  if (process.env.NODE_ENV !== 'production') console.log(`[SMS to ${phone}] ${text}`);
  // TODO: call your SMS provider here
}

// SMS abuse protection (in memory, like the codes themselves):
//  - at least 60 s between two codes for the same phone
//  - at most 5 codes per hour per phone
//  - a global daily cap so nobody can drain your SMS credit (SMS_DAILY_CAP, default 500)
const smsLog = new Map();            // phone -> timestamps of recent requests
let smsToday = { day: '', count: 0 };
const SMS_DAILY_CAP = Number(process.env.SMS_DAILY_CAP || 500);

function smsBlocked(phone) {
  const now = Date.now();
  const recent = (smsLog.get(phone) || []).filter(t => now - t < 60 * 60_000);
  if (recent.length && now - recent[recent.length - 1] < 60_000) return 'TOO_SOON';
  if (recent.length >= 5) return 'TOO_MANY';
  const day = new Date().toISOString().slice(0, 10);
  if (smsToday.day !== day) smsToday = { day, count: 0 };
  if (smsToday.count >= SMS_DAILY_CAP) return 'SMS_BUDGET';
  recent.push(now);
  smsLog.set(phone, recent);
  smsToday.count++;
  return null;
}
// forget old entries so the maps do not grow forever
setInterval(() => {
  const now = Date.now();
  for (const [p, ts] of smsLog) if (!ts.some(t => now - t < 60 * 60_000)) smsLog.delete(p);
  for (const [p, r] of otps) if (r.expires < now) otps.delete(p);
}, 10 * 60_000);

app.post('/auth/request-otp', authLimiter, wrap(async (req, res) => {
  const phone = String(req.body.phone || '').replace(/\s/g, '');
  if (!/^\+?\d{8,15}$/.test(phone)) return res.status(400).json({ error: 'INVALID_PHONE' });
  const blocked = smsBlocked(phone);
  if (blocked) return res.status(429).json({ error: blocked });
  const code = String(crypto.randomInt(100000, 1000000));
  otps.set(phone, { hash: hash(code), expires: Date.now() + 5 * 60_000, tries: 0 });
  await sendSms(phone, `رمز التحقق لتطبيق موعد طبي: ${code}`);
  res.json({ ok: true });
}));

app.post('/auth/verify-otp', authLimiter, wrap(async (req, res) => {
  const phone = String(req.body.phone || '').replace(/\s/g, '');
  const rec = otps.get(phone);
  if (!rec || rec.expires < Date.now() || rec.tries >= 5) return res.status(400).json({ error: 'OTP_EXPIRED' });
  rec.tries++;
  if (rec.hash !== hash(String(req.body.code || ''))) return res.status(400).json({ error: 'OTP_WRONG' });
  otps.delete(phone);

  const { rows } = await db.query(
    `INSERT INTO users (phone, full_name) VALUES ($1, $2)
     ON CONFLICT (phone) DO UPDATE SET phone = EXCLUDED.phone
     RETURNING id, role, full_name, is_active, privacy_accepted_at`,
    [phone, req.body.full_name || phone]);
  const user = rows[0];
  if (!user.is_active) return res.status(403).json({ error: 'ACCOUNT_DISABLED' });
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, role: user.role, full_name: user.full_name,
                            privacy_accepted: !!user.privacy_accepted_at } });
}));

function auth(...roles) {
  return async (req, res, next) => {
    try {
      const token = (req.headers.authorization || '').replace('Bearer ', '');
      req.user = jwt.verify(token, JWT_SECRET);
    } catch { return res.status(401).json({ error: 'UNAUTHENTICATED' }); }
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'FORBIDDEN' });
    try {
      // a deleted or disabled account stops working at once, even with a valid token
      const { rows } = await db.query('SELECT is_active FROM users WHERE id = $1', [req.user.sub]);
      if (!rows.length || !rows[0].is_active) return res.status(401).json({ error: 'UNAUTHENTICATED' });
    } catch (e) { return next(e); }
    next();
  };
}

// ───────────── My account: privacy consent, export, deletion ─────────────
const PRIVACY_VERSION = 'v1';   // bump this when the policy text changes to ask for consent again

app.get('/me', auth(), wrap(async (req, res) => {
  const { rows } = await db.query(
    'SELECT id, full_name, phone, privacy_accepted_at, privacy_version FROM users WHERE id = $1', [req.user.sub]);
  const u = rows[0];
  res.json({ id: u.id, full_name: u.full_name, phone: u.phone,
             privacy_accepted: !!u.privacy_accepted_at && u.privacy_version === PRIVACY_VERSION });
}));

app.post('/me/accept-privacy', auth(), wrap(async (req, res) => {
  if (req.body.version !== PRIVACY_VERSION) return res.status(400).json({ error: 'INVALID_VERSION' });
  await db.query('UPDATE users SET privacy_accepted_at = now(), privacy_version = $2 WHERE id = $1',
                 [req.user.sub, PRIVACY_VERSION]);
  res.json({ ok: true });
}));

// Right of access: everything we hold about the user, as JSON
app.get('/me/export', auth(), wrap(async (req, res) => {
  const [user, appts, pays] = await Promise.all([
    db.query('SELECT id, full_name, phone, language, created_at, privacy_accepted_at FROM users WHERE id = $1', [req.user.sub]),
    db.query(`SELECT a.id, a.status, lower(a.during) AS starts_at, d.full_name AS doctor, c.name AS clinic
              FROM appointments a JOIN doctors d ON d.id = a.doctor_id
              JOIN doctor_clinics dc ON dc.id = a.doctor_clinic_id JOIN clinics c ON c.id = dc.clinic_id
              WHERE a.patient_id = $1 ORDER BY a.created_at`, [req.user.sub]),
    db.query(`SELECT p.appointment_id, p.method_code, p.amount_mru, p.status, p.created_at
              FROM payments p JOIN appointments a ON a.id = p.appointment_id WHERE a.patient_id = $1`, [req.user.sub]),
  ]);
  res.json({ user: user.rows[0], appointments: appts.rows, payments: pays.rows });
}));

// Delete account = anonymise. Future appointments are cancelled (slots freed).
// Past appointments and payments stay (without any link to a name or phone)
// because accounting records usually have to be kept.
app.delete('/me', auth('patient'), wrap(async (req, res) => {
  if (req.body.confirm !== true) return res.status(400).json({ error: 'CONFIRM_REQUIRED' });
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE appointments SET status = 'cancelled', notes = NULL
       WHERE patient_id = $1 AND status IN ('pending_payment','confirmed') AND lower(during) > now()`, [req.user.sub]);
    await client.query(`UPDATE appointments SET notes = NULL WHERE patient_id = $1`, [req.user.sub]);
    await client.query(
      `UPDATE users SET full_name = 'مستخدم محذوف', phone = 'deleted-' || id::text,
              is_active = FALSE, deleted_at = now(), privacy_accepted_at = NULL, privacy_version = NULL
       WHERE id = $1`, [req.user.sub]);
    await client.query(
      `INSERT INTO audit_log (actor_id, action, entity, entity_id) VALUES ($1,'delete_account','users',$2)`,
      [req.user.sub, String(req.user.sub)]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
  res.json({ ok: true });
}));

// ───────────── Patient: browse doctors ─────────────
app.get('/doctors', wrap(async (req, res) => {
  const { specialty, city, q } = req.query;
  const { rows } = await db.query(
    `SELECT dc.id AS doctor_clinic_id, d.full_name AS doctor, d.specialty,
            c.name AS clinic, c.city, dc.fee_mru
     FROM doctor_clinics dc
     JOIN doctors d ON d.id = dc.doctor_id AND d.is_active AND d.is_verified
     JOIN clinics c ON c.id = dc.clinic_id AND c.is_active
     WHERE ($1::text IS NULL OR d.specialty = $1)
       AND ($2::text IS NULL OR c.city = $2)
       AND ($3::text IS NULL OR d.full_name ILIKE '%' || $3 || '%' OR c.name ILIKE '%' || $3 || '%')
     ORDER BY d.full_name LIMIT 50`,
    [specialty || null, city || null, q || null]);
  res.json(rows);
}));

// Available slots for one day (the "اختر الوقت" screen)
app.get('/doctors/:dcId/slots', wrap(async (req, res) => {
  const date = String(req.query.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'INVALID_DATE' });

  const dc = await db.query('SELECT doctor_id, slot_minutes FROM doctor_clinics WHERE id = $1', [req.params.dcId]);
  if (!dc.rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
  const { doctor_id, slot_minutes } = dc.rows[0];
  const weekday = new Date(`${date}T00:00:00Z`).getUTCDay();

  const [settings, hours, taken, off] = await Promise.all([
    B.loadSettings(db),
    db.query(`SELECT to_char(start_time,'HH24:MI') AS start_time, to_char(end_time,'HH24:MI') AS end_time
              FROM working_hours WHERE doctor_clinic_id = $1 AND weekday = $2 ORDER BY start_time`, [req.params.dcId, weekday]),
    db.query(`SELECT lower(during) AS start, upper(during) AS "end" FROM appointments
              WHERE doctor_id = $1 AND status IN ('pending_payment','confirmed') AND during && tstzrange($2, $3)`,
             [doctor_id, `${date}T00:00:00Z`, `${date}T23:59:59Z`]),
    db.query(`SELECT lower(during) AS start, upper(during) AS "end" FROM time_off
              WHERE doctor_id = $1 AND during && tstzrange($2, $3)`,
             [doctor_id, `${date}T00:00:00Z`, `${date}T23:59:59Z`]),
  ]);
  const slots = B.generateSlots({ date, hours: hours.rows, slotMinutes: slot_minutes,
                                  taken: taken.rows, timeOff: off.rows, settings });
  res.json(slots.map(s => s.start.toISOString().slice(11, 16)));
}));

// ───────────── Patient: appointments & payment ─────────────
const ERR_STATUS = { SLOT_TAKEN: 409, SLOT_NOT_AVAILABLE: 409, REFERENCE_ALREADY_USED: 409,
                     LIMIT_REACHED: 429, HOLD_EXPIRED: 410, ALREADY_SUBMITTED: 409,
                     NOTHING_TO_CONFIRM: 409, NOTHING_TO_REJECT: 409 };

app.post('/appointments', auth('patient'), wrap(async (req, res) => {
  const { doctor_clinic_id, start } = req.body;
  if (!doctor_clinic_id || isNaN(new Date(start))) return res.status(400).json({ error: 'INVALID_INPUT' });
  const consent = await db.query('SELECT privacy_version FROM users WHERE id = $1', [req.user.sub]);
  if (consent.rows[0]?.privacy_version !== PRIVACY_VERSION) return res.status(403).json({ error: 'PRIVACY_REQUIRED' });
  // urgent bookings are NOT self-declared by patients; only staff can set them (see below)
  const result = await B.bookAppointment(db, { patientId: req.user.sub, doctorClinicId: doctor_clinic_id, start });
  res.status(201).json(result);
}));

app.get('/appointments/mine', auth('patient'), wrap(async (req, res) => {
  const { rows } = await db.query(
    `SELECT a.id, a.status, lower(a.during) AS starts_at, a.hold_expires_at,
            d.full_name AS doctor, c.name AS clinic, dc.fee_mru,
            lp.status AS payment_status, lp.reject_reason
     FROM appointments a
     LEFT JOIN LATERAL (SELECT status, reject_reason FROM payments p
                        WHERE p.appointment_id = a.id ORDER BY p.created_at DESC LIMIT 1) lp ON TRUE
     JOIN doctor_clinics dc ON dc.id = a.doctor_clinic_id
     JOIN doctors d ON d.id = a.doctor_id JOIN clinics c ON c.id = dc.clinic_id
     WHERE a.patient_id = $1 ORDER BY a.created_at DESC LIMIT 50`, [req.user.sub]);
  res.json(rows);
}));

app.post('/appointments/:id/cancel', auth('patient'), wrap(async (req, res) => {
  const { rowCount } = await db.query(
    `UPDATE appointments SET status = 'cancelled'
     WHERE id = $1 AND patient_id = $2 AND status IN ('pending_payment','confirmed') AND lower(during) > now()`,
    [req.params.id, req.user.sub]);
  if (!rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
  res.json({ ok: true });
}));

app.get('/payment-methods', auth(), wrap(async (req, res) => {
  const { rows } = await db.query(
    `SELECT code, display_name, receiving_number FROM payment_methods WHERE is_enabled ORDER BY sort_order`);
  res.json(rows);
}));

app.post('/appointments/:id/pay', auth('patient'), wrap(async (req, res) => {
  // make sure the appointment belongs to this patient
  const own = await db.query('SELECT 1 FROM appointments WHERE id = $1 AND patient_id = $2', [req.params.id, req.user.sub]);
  if (!own.rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
  const ref = String(req.body.reference || '').trim();
  if (!/^[A-Za-z0-9-]{4,40}$/.test(ref)) return res.status(400).json({ error: 'INVALID_REFERENCE' });
  const payment = await B.submitPayment(db, { appointmentId: req.params.id, methodCode: req.body.method, reference: ref });
  res.status(201).json(payment);
}));

// ───────────── Admin panel (payments, settings, clinics, doctors, urgent bookings) ─────────────
require('./admin_routes')(app, { db, B, auth, wrap });

// ───────────── Errors & background job ─────────────
app.use((err, req, res, next) => {
  if (err instanceof B.BookingError) return res.status(ERR_STATUS[err.code] || 400).json({ error: err.code });
  console.error(err);
  res.status(500).json({ error: 'SERVER_ERROR' });
});

setInterval(() => B.expireUnpaid(db).catch(console.error), 60_000);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Mawaid Tibbi API on :${port}`));
