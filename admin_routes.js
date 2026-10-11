// موعد طبي — admin routes (payments, settings, clinics, doctors, hours, urgent bookings)
// Loaded from server.js:  require('./admin_routes')(app, { db, B, auth, wrap });

module.exports = function adminRoutes(app, { db, B, auth, wrap }) {
  // ───────────── Admin panel ─────────────
  const admin = auth('super_admin');

  app.get('/admin/counters', admin, wrap(async (req, res) => {
    res.json((await db.query('SELECT * FROM v_dashboard_counters')).rows[0]);
  }));

  app.get('/admin/payments', admin, wrap(async (req, res) => {
    const { rows } = await db.query(
      `SELECT p.*, u.full_name AS patient, u.phone FROM payments p
       JOIN appointments a ON a.id = p.appointment_id JOIN users u ON u.id = a.patient_id
       WHERE p.status = COALESCE($1::payment_status, 'submitted') ORDER BY p.created_at DESC LIMIT 100`,
      [req.query.status || null]);
    res.json(rows);
  }));

  app.post('/admin/payments/:id/confirm', admin, wrap(async (req, res) => {
    await B.confirmPayment(db, { paymentId: req.params.id, adminId: req.user.sub });
    res.json({ ok: true });
  }));

  app.post('/admin/payments/:id/reject', admin, wrap(async (req, res) => {
    const reason = String(req.body.reason || '').trim().slice(0, 200);
    if (!reason) return res.status(400).json({ error: 'REASON_REQUIRED' });
    await B.rejectPayment(db, { paymentId: req.params.id, adminId: req.user.sub, reason });
    res.json({ ok: true });
  }));

  app.get('/admin/settings', admin, wrap(async (req, res) => {
    res.json((await db.query('SELECT key, value, description FROM settings ORDER BY key')).rows);
  }));

  app.put('/admin/settings/:key', admin, wrap(async (req, res) => {
    if (typeof req.body.value !== 'number' || req.body.value < 0) return res.status(400).json({ error: 'INVALID_VALUE' });
    const { rowCount } = await db.query(
      'UPDATE settings SET value = $2, updated_by = $3, updated_at = now() WHERE key = $1',
      [req.params.key, JSON.stringify(req.body.value), req.user.sub]);
    if (!rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
    await db.query(`INSERT INTO audit_log (actor_id, action, entity, entity_id, details) VALUES ($1,'update_setting','settings',$2,$3)`,
                   [req.user.sub, req.params.key, JSON.stringify({ value: req.body.value })]);
    res.json({ ok: true });
  }));

  app.get('/admin/payment-methods', admin, wrap(async (req, res) => {
    res.json((await db.query('SELECT code, display_name, receiving_number, is_enabled FROM payment_methods ORDER BY sort_order')).rows);
  }));

  app.patch('/admin/payment-methods/:code', admin, wrap(async (req, res) => {
    const { is_enabled, receiving_number } = req.body;
    await db.query(
      `UPDATE payment_methods SET is_enabled = COALESCE($2, is_enabled),
              receiving_number = COALESCE($3, receiving_number) WHERE code = $1`,
      [req.params.code, typeof is_enabled === 'boolean' ? is_enabled : null, receiving_number || null]);
    await db.query(`INSERT INTO audit_log (actor_id, action, entity, entity_id, details) VALUES ($1,'update_payment_method','payment_methods',$2,$3)`,
                   [req.user.sub, req.params.code, JSON.stringify({ is_enabled, receiving_number })]);
    res.json({ ok: true });
  }));

  // ───────────── Admin: clinics, doctors, working hours ─────────────
  const audit = (actor, action, entity, id, details) =>
    db.query(`INSERT INTO audit_log (actor_id, action, entity, entity_id, details) VALUES ($1,$2,$3,$4,$5)`,
             [actor, action, entity, String(id), JSON.stringify(details || {})]);
  const text = (v, max = 200) => (typeof v === 'string' && v.trim() && v.trim().length <= max ? v.trim() : null);
  const isUuid = (v) => /^[0-9a-f-]{36}$/i.test(String(v || ''));

  app.get('/admin/clinics', admin, wrap(async (req, res) => {
    res.json((await db.query('SELECT id, name, city, address, phone, is_active FROM clinics ORDER BY created_at DESC')).rows);
  }));

  app.post('/admin/clinics', admin, wrap(async (req, res) => {
    const name = text(req.body.name), city = text(req.body.city);
    if (!name || !city) return res.status(400).json({ error: 'INVALID_INPUT' });
    const { rows } = await db.query(
      'INSERT INTO clinics (name, city, address, phone) VALUES ($1,$2,$3,$4) RETURNING *',
      [name, city, text(req.body.address, 300), text(req.body.phone, 30)]);
    await audit(req.user.sub, 'create_clinic', 'clinics', rows[0].id, { name });
    res.status(201).json(rows[0]);
  }));

  app.patch('/admin/clinics/:id', admin, wrap(async (req, res) => {
    if (!isUuid(req.params.id) || typeof req.body.is_active !== 'boolean') return res.status(400).json({ error: 'INVALID_INPUT' });
    await db.query('UPDATE clinics SET is_active = $2 WHERE id = $1', [req.params.id, req.body.is_active]);
    await audit(req.user.sub, 'toggle_clinic', 'clinics', req.params.id, { is_active: req.body.is_active });
    res.json({ ok: true });
  }));

  app.get('/admin/doctors', admin, wrap(async (req, res) => {
    res.json((await db.query('SELECT id, full_name, specialty, is_verified, is_active FROM doctors ORDER BY full_name')).rows);
  }));

  app.post('/admin/doctors', admin, wrap(async (req, res) => {
    const name = text(req.body.full_name), specialty = text(req.body.specialty, 60);
    if (!name || !specialty) return res.status(400).json({ error: 'INVALID_INPUT' });
    // doctors added by the admin are verified straight away
    const { rows } = await db.query(
      'INSERT INTO doctors (full_name, specialty, bio, is_verified) VALUES ($1,$2,$3,TRUE) RETURNING *',
      [name, specialty, text(req.body.bio, 1000)]);
    await audit(req.user.sub, 'create_doctor', 'doctors', rows[0].id, { name, specialty });
    res.status(201).json(rows[0]);
  }));

  app.patch('/admin/doctors/:id', admin, wrap(async (req, res) => {
    const { is_active, is_verified } = req.body;
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'INVALID_INPUT' });
    await db.query(
      `UPDATE doctors SET is_active = COALESCE($2, is_active), is_verified = COALESCE($3, is_verified) WHERE id = $1`,
      [req.params.id, typeof is_active === 'boolean' ? is_active : null, typeof is_verified === 'boolean' ? is_verified : null]);
    await audit(req.user.sub, 'update_doctor', 'doctors', req.params.id, { is_active, is_verified });
    res.json({ ok: true });
  }));

  // Link a doctor to a clinic with a fee and slot length
  app.get('/admin/doctor-clinics', admin, wrap(async (req, res) => {
    res.json((await db.query(
      `SELECT dc.id, d.full_name AS doctor, c.name AS clinic, dc.fee_mru, dc.slot_minutes
       FROM doctor_clinics dc JOIN doctors d ON d.id = dc.doctor_id JOIN clinics c ON c.id = dc.clinic_id
       ORDER BY d.full_name`)).rows);
  }));

  app.post('/admin/doctor-clinics', admin, wrap(async (req, res) => {
    const { doctor_id, clinic_id } = req.body;
    const fee = Number(req.body.fee_mru), slot = Number(req.body.slot_minutes || 30);
    if (!isUuid(doctor_id) || !isUuid(clinic_id) || !Number.isInteger(fee) || fee < 0 ||
        !Number.isInteger(slot) || slot < 5 || slot > 240) return res.status(400).json({ error: 'INVALID_INPUT' });
    try {
      const { rows } = await db.query(
        'INSERT INTO doctor_clinics (doctor_id, clinic_id, fee_mru, slot_minutes) VALUES ($1,$2,$3,$4) RETURNING *',
        [doctor_id, clinic_id, fee, slot]);
      await audit(req.user.sub, 'link_doctor_clinic', 'doctor_clinics', rows[0].id, { fee, slot });
      res.status(201).json(rows[0]);
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'ALREADY_LINKED' });
      if (e.code === '23503') return res.status(400).json({ error: 'INVALID_INPUT' });
      throw e;
    }
  }));

  app.patch('/admin/doctor-clinics/:id', admin, wrap(async (req, res) => {
    const fee = Number(req.body.fee_mru), slot = Number(req.body.slot_minutes);
    if (!isUuid(req.params.id) || !Number.isInteger(fee) || fee < 0 || !Number.isInteger(slot) || slot < 5 || slot > 240)
      return res.status(400).json({ error: 'INVALID_INPUT' });
    await db.query('UPDATE doctor_clinics SET fee_mru = $2, slot_minutes = $3 WHERE id = $1', [req.params.id, fee, slot]);
    await audit(req.user.sub, 'update_doctor_clinic', 'doctor_clinics', req.params.id, { fee, slot });
    res.json({ ok: true });
  }));

  app.get('/admin/doctor-clinics/:id/hours', admin, wrap(async (req, res) => {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'INVALID_INPUT' });
    res.json((await db.query(
      `SELECT weekday, to_char(start_time,'HH24:MI') AS start_time, to_char(end_time,'HH24:MI') AS end_time
       FROM working_hours WHERE doctor_clinic_id = $1 ORDER BY weekday, start_time`, [req.params.id])).rows);
  }));

  // Replace the whole weekly schedule at once
  app.put('/admin/doctor-clinics/:id/hours', admin, wrap(async (req, res) => {
    const hours = req.body.hours;
    const okTime = (t) => /^([01]\d|2[0-3]):[0-5]\d$/.test(t);
    if (!isUuid(req.params.id) || !Array.isArray(hours) || hours.length > 28 ||
        !hours.every(h => Number.isInteger(h.weekday) && h.weekday >= 0 && h.weekday <= 6 &&
                          okTime(h.start_time) && okTime(h.end_time) && h.end_time > h.start_time))
      return res.status(400).json({ error: 'INVALID_HOURS' });

    const client = await db.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM working_hours WHERE doctor_clinic_id = $1', [req.params.id]);
      for (const h of hours) {
        await client.query(
          'INSERT INTO working_hours (doctor_clinic_id, weekday, start_time, end_time) VALUES ($1,$2,$3,$4)',
          [req.params.id, h.weekday, h.start_time, h.end_time]);
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }
    await audit(req.user.sub, 'update_hours', 'doctor_clinics', req.params.id, { rows: hours.length });
    res.json({ ok: true });
  }));

  // ───────────── Admin: urgent / walk-in bookings ─────────────
  // Slots for staff include the ones reserved for urgent cases, and ignore the minimum lead time.
  app.get('/admin/doctor-clinics/:id/slots', admin, wrap(async (req, res) => {
    const date = String(req.query.date || '');
    if (!isUuid(req.params.id) || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'INVALID_INPUT' });
    const dc = await db.query('SELECT doctor_id, slot_minutes FROM doctor_clinics WHERE id = $1', [req.params.id]);
    if (!dc.rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
    const { doctor_id, slot_minutes } = dc.rows[0];
    const range = [`${date}T00:00:00Z`, `${date}T23:59:59Z`];

    const [settings, hours, taken, off] = await Promise.all([
      B.loadSettings(db),
      db.query(`SELECT to_char(start_time,'HH24:MI') AS start_time, to_char(end_time,'HH24:MI') AS end_time
                FROM working_hours WHERE doctor_clinic_id = $1 AND weekday = $2 ORDER BY start_time`,
               [req.params.id, new Date(`${date}T00:00:00Z`).getUTCDay()]),
      db.query(`SELECT lower(during) AS start, upper(during) AS "end" FROM appointments
                WHERE doctor_id = $1 AND status IN ('pending_payment','confirmed') AND during && tstzrange($2, $3)`,
               [doctor_id, ...range]),
      db.query(`SELECT lower(during) AS start, upper(during) AS "end" FROM time_off
                WHERE doctor_id = $1 AND during && tstzrange($2, $3)`, [doctor_id, ...range]),
    ]);
    const slots = B.generateSlots({ date, hours: hours.rows, slotMinutes: slot_minutes,
                                    taken: taken.rows, timeOff: off.rows, settings, urgent: true });
    res.json(slots.map(s => s.start.toISOString().slice(11, 16)));
  }));

  app.post('/admin/appointments', admin, wrap(async (req, res) => {
    const { doctor_clinic_id, start } = req.body;
    const phone = String(req.body.phone || '').replace(/\s/g, '');
    if (!isUuid(doctor_clinic_id) || isNaN(new Date(start)) || !/^\+?\d{8,15}$/.test(phone))
      return res.status(400).json({ error: 'INVALID_INPUT' });

    // find the patient by phone, or create the account (they accept the privacy policy at first login)
    const u = await db.query(
      `INSERT INTO users (phone, full_name) VALUES ($1, $2)
       ON CONFLICT (phone) DO UPDATE SET phone = EXCLUDED.phone RETURNING id, role, is_active`,
      [phone, text(req.body.full_name, 100) || phone]);
    if (!u.rows[0].is_active || u.rows[0].role !== 'patient') return res.status(400).json({ error: 'INVALID_PATIENT' });

    const result = await B.bookAppointment(db, {
      patientId: u.rows[0].id, doctorClinicId: doctor_clinic_id, start, urgent: true, byStaff: true });
    await audit(req.user.sub, 'staff_booking', 'appointments', result.appointment.id, { urgent: true });
    res.status(201).json({ appointment_id: result.appointment.id });
  }));

};
