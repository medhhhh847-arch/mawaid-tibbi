// موعد طبي — booking & payment algorithm
// Node.js + "pg". Mauritania is on UTC+0 all year (no daylight saving),
// so working hours can be treated as UTC without conversion.

const MIN = 60 * 1000;

// ───────────── Settings (all controlled from the admin panel) ─────────────
async function loadSettings(db) {
  const { rows } = await db.query('SELECT key, value FROM settings');
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
}

// ───────────── 1. Generate the available slots for one doctor/day ─────────────
// Pure function: no database access, easy to test.
//   hours   : [{start_time:'09:00', end_time:'13:00'}, ...] for that weekday
//   taken   : [{start:Date, end:Date}] active appointments that day
//   timeOff : [{start:Date, end:Date}]
function generateSlots({ date, hours, slotMinutes, taken, timeOff, settings, now = new Date(), urgent = false }) {
  const slots = [];
  // urgent cases can be booked right away, without the usual minimum lead time
  const earliest = new Date(now.getTime() + (urgent ? 0 : settings.min_lead_minutes) * MIN);
  const latest   = new Date(now.getTime() + settings.max_days_ahead * 24 * 60 * MIN);

  for (const h of hours) {
    let cursor = new Date(`${date}T${h.start_time}:00Z`);
    const end  = new Date(`${date}T${h.end_time}:00Z`);

    while (cursor.getTime() + slotMinutes * MIN <= end.getTime()) {
      const slot = { start: new Date(cursor), end: new Date(cursor.getTime() + slotMinutes * MIN) };
      const overlaps = (r) => slot.start < r.end && slot.end > r.start;

      if (slot.start >= earliest && slot.start <= latest &&
          !taken.some(overlaps) && !timeOff.some(overlaps)) {
        slots.push(slot);
      }
      cursor = slot.end;
    }
  }

  // Keep the LAST N slots of the day for urgent cases only.
  const reserved = settings.urgent_reserved_slots || 0;
  return urgent || reserved === 0 ? slots : slots.slice(0, Math.max(0, slots.length - reserved));
}

// ───────────── 2. Book (transaction + database-level protection) ─────────────
// byStaff = booked by the administration (urgent / walk-in): the appointment is
// confirmed immediately, with no payment hold and no per-patient limit.
async function bookAppointment(db, { patientId, doctorClinicId, start, urgent = false, byStaff = false }) {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const settings = await loadSettings(client);

    // Limit active appointments per patient (patients only)
    if (!byStaff) {
      const active = await client.query(
        `SELECT count(*)::int AS n FROM appointments
         WHERE patient_id = $1 AND status IN ('pending_payment','confirmed') AND upper(during) > now()`,
        [patientId]);
      if (active.rows[0].n >= settings.max_active_per_patient) throw new BookingError('LIMIT_REACHED');
    }

    const dc = await client.query(
      `SELECT dc.*, d.is_active AND d.is_verified AS doctor_ok
       FROM doctor_clinics dc JOIN doctors d ON d.id = dc.doctor_id WHERE dc.id = $1`,
      [doctorClinicId]);
    if (!dc.rowCount || !dc.rows[0].doctor_ok) throw new BookingError('DOCTOR_UNAVAILABLE');
    const { doctor_id, slot_minutes, fee_mru } = dc.rows[0];

    const startAt = new Date(start);
    const endAt   = new Date(startAt.getTime() + slot_minutes * MIN);

    // Re-check that this exact slot is still offered (hours, time off, lead time, urgent reserve)
    const date = startAt.toISOString().slice(0, 10);
    const [hours, taken, off] = await Promise.all([
      client.query(`SELECT to_char(start_time,'HH24:MI') AS start_time, to_char(end_time,'HH24:MI') AS end_time
                    FROM working_hours WHERE doctor_clinic_id = $1 AND weekday = $2 ORDER BY start_time`,
                   [doctorClinicId, startAt.getUTCDay()]),
      client.query(`SELECT lower(during) AS start, upper(during) AS "end" FROM appointments
                    WHERE doctor_id = $1 AND status IN ('pending_payment','confirmed')
                      AND during && tstzrange($2, $3)`, [doctor_id, `${date}T00:00:00Z`, `${date}T23:59:59Z`]),
      client.query(`SELECT lower(during) AS start, upper(during) AS "end" FROM time_off
                    WHERE doctor_id = $1 AND during && tstzrange($2, $3)`,
                   [doctor_id, `${date}T00:00:00Z`, `${date}T23:59:59Z`]),
    ]);
    const offered = generateSlots({
      date, hours: hours.rows, slotMinutes: slot_minutes,
      taken: taken.rows, timeOff: off.rows, settings, urgent,
    });
    if (!offered.some(s => s.start.getTime() === startAt.getTime())) throw new BookingError('SLOT_NOT_AVAILABLE');

    // Insert. If two patients race for the same slot, the EXCLUDE constraint
    // rejects the second one (error code 23P01) — no double-booking is possible.
    const holdUntil = new Date(Date.now() + settings.hold_minutes * MIN);
    const appt = await client.query(
      `INSERT INTO appointments (patient_id, doctor_clinic_id, doctor_id, during, priority, status, hold_expires_at, notes)
       VALUES ($1, $2, $3, tstzrange($4, $5), $6, $7, $8, $9) RETURNING *`,
      [patientId, doctorClinicId, doctor_id, startAt, endAt,
       urgent ? 'urgent' : 'normal',
       byStaff ? 'confirmed' : 'pending_payment',
       byStaff ? null : holdUntil,
       byStaff ? 'حجز من الإدارة' : null]);

    await client.query('COMMIT');
    return { appointment: appt.rows[0], fee_mru, hold_until: holdUntil };
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23P01') throw new BookingError('SLOT_TAKEN');
    throw err;
  } finally {
    client.release();
  }
}

// ───────────── 3. Payment algorithm ─────────────
function computeAmounts(feeMru, commissionPercent) {
  const commission = Math.round(feeMru * commissionPercent / 100);
  return { amount_mru: feeMru, commission_mru: commission, clinic_net_mru: feeMru - commission };
}

// Patient transferred the money and typed the transaction number
async function submitPayment(db, { appointmentId, methodCode, reference }) {
  const settings = await loadSettings(db);
  const method = await db.query('SELECT * FROM payment_methods WHERE code = $1 AND is_enabled', [methodCode]);
  if (!method.rowCount) throw new BookingError('METHOD_DISABLED');

  const appt = await db.query(
    `SELECT a.id, dc.fee_mru FROM appointments a JOIN doctor_clinics dc ON dc.id = a.doctor_clinic_id
     WHERE a.id = $1 AND a.status = 'pending_payment' AND a.hold_expires_at > now()`, [appointmentId]);
  if (!appt.rowCount) throw new BookingError('HOLD_EXPIRED');

  // only one payment can be under review at a time
  const open = await db.query(
    `SELECT 1 FROM payments WHERE appointment_id = $1 AND status = 'submitted'`, [appointmentId]);
  if (open.rowCount) throw new BookingError('ALREADY_SUBMITTED');

  const amounts = computeAmounts(appt.rows[0].fee_mru, settings.commission_percent);
  try {
    const { rows } = await db.query(
      `INSERT INTO payments (appointment_id, method_code, amount_mru, commission_mru, reference, status)
       VALUES ($1, $2, $3, $4, $5, 'submitted') RETURNING *`,
      [appointmentId, methodCode, amounts.amount_mru, amounts.commission_mru, reference]);
    return rows[0];
  } catch (err) {
    if (err.code === '23505') throw new BookingError('REFERENCE_ALREADY_USED');
    throw err;
  }
}

// Admin (or later: the payment provider's webhook) confirms the money arrived
async function confirmPayment(db, { paymentId, adminId }) {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const p = await client.query(
      `UPDATE payments SET status = 'confirmed', confirmed_by = $2, confirmed_at = now()
       WHERE id = $1 AND status = 'submitted' RETURNING appointment_id`, [paymentId, adminId]);
    if (!p.rowCount) throw new BookingError('NOTHING_TO_CONFIRM');
    await client.query(
      `UPDATE appointments SET status = 'confirmed', hold_expires_at = NULL WHERE id = $1`,
      [p.rows[0].appointment_id]);
    await client.query(
      `INSERT INTO audit_log (actor_id, action, entity, entity_id) VALUES ($1, 'confirm_payment', 'payment', $2)`,
      [adminId, paymentId]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}

// Admin rejects a payment (wrong amount, fake or unknown reference...).
// The appointment is NOT cancelled at once: the patient gets a grace period to
// pay again, and if they don't, expireUnpaid() releases the slot automatically.
async function rejectPayment(db, { paymentId, adminId, reason }) {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const settings = await loadSettings(client);
    const p = await client.query(
      `UPDATE payments SET status = 'rejected', reject_reason = $2, confirmed_by = $3, confirmed_at = now()
       WHERE id = $1 AND status = 'submitted' RETURNING appointment_id`,
      [paymentId, reason, adminId]);
    if (!p.rowCount) throw new BookingError('NOTHING_TO_REJECT');

    const grace = new Date(Date.now() + settings.reject_grace_minutes * MIN);
    // keep whichever deadline is later: the current one or the grace period
    await client.query(
      `UPDATE appointments SET hold_expires_at = GREATEST(COALESCE(hold_expires_at, now()), $2)
       WHERE id = $1 AND status = 'pending_payment'`,
      [p.rows[0].appointment_id, grace]);
    await client.query(
      `INSERT INTO audit_log (actor_id, action, entity, entity_id, details) VALUES ($1,'reject_payment','payment',$2,$3)`,
      [adminId, paymentId, JSON.stringify({ reason })]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}

// ───────────── 4. Release unpaid slots (run every minute with cron / setInterval) ─────────────
async function expireUnpaid(db) {
  const { rowCount } = await db.query(
    `UPDATE appointments SET status = 'expired'
     WHERE status = 'pending_payment' AND hold_expires_at < now()
       AND NOT EXISTS (SELECT 1 FROM payments p WHERE p.appointment_id = appointments.id AND p.status = 'submitted')`);
  return rowCount;
}

class BookingError extends Error {
  constructor(code) { super(code); this.code = code; }
}

module.exports = { loadSettings, generateSlots, bookAppointment, computeAmounts,
                   submitPayment, confirmPayment, rejectPayment, expireUnpaid, BookingError };
