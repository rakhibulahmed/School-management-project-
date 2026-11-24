import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import multer from 'multer';
import { WebSocket, WebSocketServer } from 'ws';
import { createServer as createViteServer } from 'vite';
import {
  createAdmissionApplication,
  createNote,
  createNotice,
  createSchoolClass,
  createStudentRecord,
  createUserAccount,
  db,
  deleteNotice,
  deleteSchoolClass,
  deleteStudentRecord,
  deleteUserAccount,
  findAdmissionByRefAndEmail,
  findUserByEmail,
  findUserById,
  getStudentById,
  hasAnyAdmin,
  initDatabase,
  listAdmissions,
  listAllUsers,
  listAttendance,
  listGrades,
  listMessagesForUser,
  listNotes,
  listNotices,
  listSchoolClasses,
  listStudents,
  logAudit,
  saveAttendanceBatch,
  saveChatMessage,
  UPLOADS_DIR,
  updateAdmissionStatus,
  updateStudentRecord,
  updateUserPermissions,
  upsertGrade,
} from './server/db';
import {
  blindIndex,
  generateOtp,
  hashOtp,
  signSessionToken,
  verifyOtpHash,
  verifyPassword,
  verifySessionToken,
} from './server/crypto';
import {
  canTeacherGradeStudentSubject,
  evaluateAdmissionReadiness,
  generateAutomatedReportCard,
  generateTeacherDefaultPassword,
  validateTwelveDigitId,
} from './src/utils/academics';
import type {
  AdmissionApplication,
  AttendanceStatus,
  NoticePriority,
  UploadedDocumentMeta,
  UserRole,
  UserSession,
} from './src/types/school';

declare global {
  namespace Express {
    interface Request {
      user?: UserSession;
    }
  }
}

initDatabase();

const app = express();
app.use(express.json({ limit: '2mb' }));

// In-memory preview OTP outbox used ONLY when SMTP_HOST is not configured
const previewOtpOutbox = new Map<
  string,
  { email: string; otp: string; fullName: string; createdAt: number }
>();

// Uploaded file metadata registry for safe MIME & original name lookup
const uploadedFilesMeta = new Map<
  string,
  { fileId: string; storedName: string; originalName: string; mimeType: string; sizeBytes: number }
>();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

const ALLOWED_MIME_TYPES = new Set(['application/pdf', 'image/png', 'image/jpeg']);
const MIME_TO_EXT: Record<string, string> = {
  'application/pdf': '.pdf',
  'image/png': '.png',
  'image/jpeg': '.jpg',
};

function saveBufferSafely(file: Express.Multer.File) {
  if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
    throw new Error('Only PDF, PNG, and JPEG files are permitted.');
  }
  const fileId = crypto.randomUUID();
  const ext = MIME_TO_EXT[file.mimetype] || '.bin';
  const storedName = `${fileId}${ext}`;
  const targetPath = path.resolve(UPLOADS_DIR, storedName);
  if (!targetPath.startsWith(UPLOADS_DIR + path.sep)) {
    throw new Error('Invalid upload path.');
  }
  fs.writeFileSync(targetPath, file.buffer);
  const meta = {
    fileId,
    storedName,
    originalName: path.basename(file.originalname).slice(0, 120),
    mimeType: file.mimetype,
    sizeBytes: file.size,
  };
  uploadedFilesMeta.set(fileId, meta);
  return meta;
}

function issueOtpChallenge(userId: string, email: string, fullName: string) {
  const challengeId = `chl-${crypto.randomUUID()}`;
  const otp = generateOtp();
  const expiresAt = Date.now() + 5 * 60 * 1000;

  db.prepare(
    'INSERT INTO otp_challenges (id, user_id, email_hmac, otp_hash, expires_at, attempts, verified) VALUES (?, ?, ?, ?, ?, 0, 0)',
  ).run(challengeId, userId, blindIndex(email), hashOtp(otp, challengeId), expiresAt);

  const smtpConfigured = Boolean(process.env.SMTP_HOST?.trim());
  if (!smtpConfigured) {
    previewOtpOutbox.set(challengeId, {
      email,
      otp,
      fullName,
      createdAt: Date.now(),
    });
  }

  return {
    challengeId,
    deliveryMode: smtpConfigured ? ('smtp' as const) : ('preview' as const),
    expiresInSeconds: 300,
  };
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  const token = authHeader.slice('Bearer '.length).trim();
  const payload = verifySessionToken(token);
  if (!payload) {
    res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
    return;
  }
  const user = findUserById(payload.userId);
  if (!user) {
    res.status(401).json({ error: 'Account no longer exists.' });
    return;
  }
  req.user = user;
  next();
}

function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Access denied for your portal role.' });
      return;
    }
    next();
  };
}

function canAccessStudent(user: UserSession, studentId: string): boolean {
  if (user.role === 'admin' || user.role === 'teacher') return true;
  return user.linkedStudentIds.includes(studentId);
}

// WebSocket hub for real-time messaging & live notice board updates
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const userSockets = new Map<string, Set<WebSocket>>();

function broadcastAll(event: string, data: unknown) {
  const frame = JSON.stringify({ event, data });
  for (const sockets of userSockets.values()) {
    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(frame);
      }
    }
  }
}

function broadcastToUsers(userIds: string[], event: string, data: unknown) {
  const frame = JSON.stringify({ event, data });
  const uniqueIds = new Set(userIds);
  for (const uid of uniqueIds) {
    const sockets = userSockets.get(uid);
    if (!sockets) continue;
    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(frame);
      }
    }
  }
}

function broadcastPresence() {
  const onlineUserIds = Array.from(userSockets.entries())
    .filter(([, set]) => set.size > 0)
    .map(([uid]) => uid);
  broadcastAll('presence:update', { onlineUserIds });
}

server.on('upgrade', (request, socket, head) => {
  const reqUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
  if (reqUrl.pathname !== '/ws') {
    return;
  }
  const token = reqUrl.searchParams.get('token') || '';
  const payload = verifySessionToken(token);
  if (!payload) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  const user = findUserById(payload.userId);
  if (!user) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, user);
  });
});

wss.on('connection', (ws: WebSocket, user: UserSession) => {
  const existing = userSockets.get(user.id) || new Set<WebSocket>();
  existing.add(ws);
  userSockets.set(user.id, existing);
  broadcastPresence();

  ws.on('close', () => {
    const set = userSockets.get(user.id);
    if (set) {
      set.delete(ws);
      if (set.size === 0) userSockets.delete(user.id);
    }
    broadcastPresence();
  });
});

// ================= AUTHENTICATION & OTP ROUTES =================

app.get('/api/auth/status', (_req, res) => {
  res.json({
    initialized: hasAnyAdmin() || Boolean(process.env.ADMIN_PASSCODE?.trim()),
    smtpConfigured: Boolean(process.env.SMTP_HOST?.trim()),
  });
});

app.post('/api/auth/bootstrap-admin', (req, res) => {
  if (hasAnyAdmin() || process.env.ADMIN_PASSCODE?.trim()) {
    res.status(409).json({ error: 'Administrator account is already initialized.' });
    return;
  }
  const { fullName, email, password, createDemoAccounts } = req.body as {
    fullName?: string;
    email?: string;
    password?: string;
    createDemoAccounts?: boolean;
  };
  if (!fullName?.trim() || !email?.trim() || !password || password.length < 8) {
    res.status(400).json({
      error: 'Provide full name, valid email, and a password of at least 8 characters.',
    });
    return;
  }

  const admin = createUserAccount({
    fullName: fullName.trim(),
    email: email.trim().toLowerCase(),
    password,
    designation: 'Administrator',
    role: 'admin',
  });

  if (createDemoAccounts) {
    if (!findUserByEmail('teacher@pioneeracademy.edu.in')) {
      createUserAccount({
        id: 'seed-teacher-1',
        fullName: 'Mr. Monowarul Sk.',
        email: 'teacher@pioneeracademy.edu.in',
        password,
        designation: 'Assistant Teacher · Mathematics',
        role: 'teacher',
        subjectSpecialty: 'B.Sc. Mathematics',
        allowedClasses: ['STANDARD 10'],
        allowedSubjects: ['Mathematics'],
      });
    }
    if (!findUserByEmail('parent@pioneeracademy.edu.in')) {
      createUserAccount({
        id: 'seed-parent-1',
        fullName: 'Pradip Kalita',
        email: 'parent@pioneeracademy.edu.in',
        password,
        designation: 'Parent / Guardian',
        role: 'parent',
        linkedStudentIds: ['stu-1', 'stu-2'],
      });
    }
    if (!findUserByEmail('student@pioneeracademy.edu.in')) {
      createUserAccount({
        id: 'seed-student-1',
        fullName: 'Aarav Kalita',
        email: 'student@pioneeracademy.edu.in',
        password,
        designation: 'Student',
        role: 'student',
        linkedStudentIds: ['stu-1'],
      });
    }
  }

  const challenge = issueOtpChallenge(admin.id, admin.email, admin.fullName);
  logAudit(admin.id, 'admin', 'BOOTSTRAP_ADMIN', admin.id);
  res.json({
    ...challenge,
    email: admin.email,
    roleHint: admin.role,
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email?.trim() || !password) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = findUserByEmail(cleanEmail);
  const envPasscode = process.env.ADMIN_PASSCODE?.trim();

  if (!user) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }

  let passwordValid = verifyPassword(password, user.passwordHash);
  if (user.role === 'admin' && envPasscode && password === envPasscode) {
    passwordValid = true;
  }

  if (!passwordValid) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }

  const challenge = issueOtpChallenge(user.id, user.profile.email, user.profile.fullName);
  res.json({
    ...challenge,
    email: user.profile.email,
    roleHint: user.role,
  });
});

app.get('/api/auth/preview-otp/:challengeId', (req, res) => {
  if (process.env.SMTP_HOST?.trim()) {
    res.status(404).json({ error: 'Not available when SMTP is configured.' });
    return;
  }
  const entry = previewOtpOutbox.get(req.params.challengeId);
  if (!entry) {
    res.status(404).json({ error: 'OTP dispatch record not found or already verified.' });
    return;
  }
  res.json({
    to: entry.email,
    subject: 'Pioneer Academy, Sonapur — Verification Code',
    otp: entry.otp,
    recipientName: entry.fullName,
  });
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { challengeId, otp } = req.body as { challengeId?: string; otp?: string };
  if (!challengeId || !otp || !/^\d{6}$/.test(otp.trim())) {
    res.status(400).json({ error: 'Enter the 6-digit verification code.' });
    return;
  }

  const row = db
    .prepare('SELECT id, user_id, otp_hash, expires_at, attempts, verified FROM otp_challenges WHERE id = ?')
    .get(challengeId) as
    | {
        id: string;
        user_id: string;
        otp_hash: string;
        expires_at: number;
        attempts: number;
        verified: number;
      }
    | undefined;

  if (!row || row.verified) {
    res.status(400).json({ error: 'Verification challenge is invalid or already used.' });
    return;
  }
  if (Date.now() > row.expires_at) {
    res.status(400).json({ error: 'Verification code expired. Request a new code.' });
    return;
  }
  if (row.attempts >= 5) {
    res.status(429).json({ error: 'Too many failed attempts. Please sign in again.' });
    return;
  }

  if (!verifyOtpHash(otp, challengeId, row.otp_hash)) {
    db.prepare('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?').run(challengeId);
    res.status(401).json({ error: 'Incorrect 6-digit verification code.' });
    return;
  }

  db.prepare('UPDATE otp_challenges SET verified = 1 WHERE id = ?').run(challengeId);
  previewOtpOutbox.delete(challengeId);

  const user = findUserById(row.user_id);
  if (!user) {
    res.status(404).json({ error: 'User account not found.' });
    return;
  }

  const token = signSessionToken({ userId: user.id, role: user.role });
  logAudit(user.id, user.role, 'OTP_LOGIN_VERIFIED', user.id);
  res.json({ token, user });
});

app.post('/api/auth/resend-otp', (req, res) => {
  const { challengeId } = req.body as { challengeId?: string };
  if (!challengeId) {
    res.status(400).json({ error: 'Challenge ID required.' });
    return;
  }
  const existing = db
    .prepare('SELECT user_id FROM otp_challenges WHERE id = ? AND verified = 0')
    .get(challengeId) as { user_id: string } | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Challenge not found.' });
    return;
  }
  const user = findUserById(existing.user_id);
  if (!user) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }
  previewOtpOutbox.delete(challengeId);
  const next = issueOtpChallenge(user.id, user.email, user.fullName);
  res.json({
    ...next,
    email: user.email,
    roleHint: user.role,
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ================= STUDENTS & ENCRYPTED VAULT =================

app.get('/api/students', requireAuth, (req, res) => {
  const user = req.user!;
  const all = listStudents(false);
  const filtered =
    user.role === 'admin' || user.role === 'teacher'
      ? all
      : all.filter((s) => user.linkedStudentIds.includes(s.id));
  res.json({ students: filtered });
});

app.post('/api/students', requireAuth, requireRole('admin'), (req, res) => {
  const {
    fullName,
    rollNumber,
    className,
    section,
    dob,
    aaparId,
    aadharId,
    parentName,
    parentEmail,
    parentPhone,
    academicHistory,
  } = req.body as {
    fullName?: string;
    rollNumber?: string;
    className?: string;
    section?: string;
    dob?: string;
    aaparId?: string;
    aadharId?: string;
    parentName?: string;
    parentEmail?: string;
    parentPhone?: string;
    academicHistory?: Array<{
      academicYear: string;
      className: string;
      percentage: number;
      gpa: number;
      rank: string;
      conduct: string;
      remarks: string;
    }>;
  };

  if (!fullName?.trim() || !rollNumber?.trim() || !className?.trim()) {
    res.status(400).json({ error: 'Student name, roll number, and class are required.' });
    return;
  }
  const aaparCheck = validateTwelveDigitId(aaparId || '');
  const aadharCheck = validateTwelveDigitId(aadharId || '');
  if (!aaparCheck.valid || !aadharCheck.valid) {
    res.status(400).json({ error: 'Both APAAR ID and Aadhaar ID must be valid 12-digit numbers.' });
    return;
  }

  try {
    const student = createStudentRecord({
      fullName: fullName.trim(),
      rollNumber: rollNumber.trim().toUpperCase(),
      className: className.trim().toUpperCase(),
      section: (section || '').trim().toUpperCase(),
      dob: dob || '2011-01-01',
      aaparId: aaparCheck.digits,
      aadharId: aadharCheck.digits,
      parentName: parentName?.trim() || 'Guardian',
      parentEmail: parentEmail?.trim().toLowerCase() || 'guardian@example.com',
      parentPhone: parentPhone?.trim() || '—',
      status: 'Active',
      academicHistory: academicHistory || [],
    });
    logAudit(req.user!.id, req.user!.role, 'CREATE_ENCRYPTED_STUDENT', student.id);
    res.status(201).json({ student });
  } catch {
    res.status(409).json({ error: 'A student with that roll number already exists in this class.' });
  }
});

app.post('/api/students/:id/reveal', requireAuth, (req, res) => {
  const user = req.user!;
  if (user.role !== 'admin' && !user.linkedStudentIds.includes(req.params.id)) {
    res.status(403).json({ error: 'Only Administrators or linked Guardians/Students may reveal full government IDs.' });
    return;
  }
  const student = getStudentById(req.params.id, true);
  if (!student) {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }
  logAudit(user.id, user.role, 'REVEAL_ENCRYPTED_IDS', student.id);
  res.json({ aaparId: student.aaparId, aadharId: student.aadharId });
});

app.get('/api/classes', (_req, res) => {
  res.json({ classes: listSchoolClasses() });
});

app.post('/api/classes', requireAuth, requireRole('admin'), (req, res) => {
  const { name } = req.body as { name?: string };
  if (!name?.trim()) {
    res.status(400).json({ error: 'Class name is required.' });
    return;
  }
  try {
    const schoolClass = createSchoolClass(name);
    logAudit(req.user!.id, req.user!.role, 'CREATE_SCHOOL_CLASS', schoolClass.id);
    broadcastAll('class:created', schoolClass);
    res.status(201).json({ schoolClass });
  } catch (err) {
    res.status(409).json({ error: (err as Error).message });
  }
});

app.delete('/api/classes/:id', requireAuth, requireRole('admin'), (req, res) => {
  const allClasses = listSchoolClasses();
  const target = allClasses.find((c) => c.id === req.params.id);
  if (!target) {
    res.status(404).json({ error: 'Class not found.' });
    return;
  }
  const hasStudents = listStudents(false).some(
    (s) => s.className.toUpperCase() === target.name.toUpperCase(),
  );
  if (hasStudents) {
    res.status(400).json({
      error: `Cannot delete ${target.name} while students are enrolled under it. Move or remove those students first.`,
    });
    return;
  }
  deleteSchoolClass(req.params.id);
  logAudit(req.user!.id, req.user!.role, 'DELETE_SCHOOL_CLASS', req.params.id);
  broadcastAll('class:deleted', { id: req.params.id });
  res.json({ deleted: true, id: req.params.id });
});

app.patch('/api/students/:id', requireAuth, requireRole('admin'), (req, res) => {
  const {
    fullName,
    rollNumber,
    className,
    section,
    dob,
    aaparId,
    aadharId,
    parentName,
    parentEmail,
    parentPhone,
    status,
  } = req.body as {
    fullName?: string;
    rollNumber?: string;
    className?: string;
    section?: string;
    dob?: string;
    aaparId?: string;
    aadharId?: string;
    parentName?: string;
    parentEmail?: string;
    parentPhone?: string;
    status?: 'Active' | 'Alumni' | 'Transferred';
  };

  let validatedAapar: string | undefined;
  let validatedAadhar: string | undefined;
  if (aaparId?.trim()) {
    const check = validateTwelveDigitId(aaparId);
    if (!check.valid) {
      res.status(400).json({ error: 'APAAR ID must be 12 numeric digits.' });
      return;
    }
    validatedAapar = check.digits;
  }
  if (aadharId?.trim()) {
    const check = validateTwelveDigitId(aadharId);
    if (!check.valid) {
      res.status(400).json({ error: 'Aadhaar number must be 12 numeric digits.' });
      return;
    }
    validatedAadhar = check.digits;
  }

  try {
    const updated = updateStudentRecord(req.params.id, {
      fullName,
      rollNumber,
      className,
      section,
      dob,
      aaparId: validatedAapar,
      aadharId: validatedAadhar,
      parentName,
      parentEmail,
      parentPhone,
      status,
    });
    if (!updated) {
      res.status(404).json({ error: 'Student record not found.' });
      return;
    }
    logAudit(req.user!.id, req.user!.role, 'UPDATE_ENCRYPTED_STUDENT', req.params.id);
    broadcastAll('student:updated', updated);
    res.json({ student: updated });
  } catch {
    res.status(409).json({ error: 'Another student in this class already has that roll number.' });
  }
});

app.delete('/api/students/:id', requireAuth, requireRole('admin'), (req, res) => {
  const deleted = deleteStudentRecord(req.params.id);
  if (!deleted) {
    res.status(404).json({ error: 'Student record not found.' });
    return;
  }
  logAudit(req.user!.id, req.user!.role, 'DELETE_ENCRYPTED_STUDENT', req.params.id);
  broadcastAll('student:deleted', { id: req.params.id });
  res.json({ deleted: true, id: req.params.id });
});

// ================= GRADING =================

app.get('/api/grades', requireAuth, (req, res) => {
  const user = req.user!;
  const allowed =
    user.role === 'admin' || user.role === 'teacher' ? undefined : user.linkedStudentIds;
  res.json({ grades: listGrades(allowed) });
});

app.post('/api/grades', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { studentId, term, subject, marksObtained, maxMarks, remarks } = req.body as {
    studentId?: string;
    term?: string;
    subject?: string;
    marksObtained?: number;
    maxMarks?: number;
    remarks?: string;
  };
  if (!studentId || !term?.trim() || !subject?.trim()) {
    res.status(400).json({ error: 'Student, term, and subject are required.' });
    return;
  }
  const obtained = Number(marksObtained);
  const max = Number(maxMarks);
  if (!Number.isFinite(obtained) || !Number.isFinite(max) || max <= 0 || obtained < 0 || obtained > max) {
    res.status(400).json({ error: 'Marks obtained must be between 0 and maximum marks.' });
    return;
  }
  const student = getStudentById(studentId, false);
  if (!student) {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }
  const permission = canTeacherGradeStudentSubject({
    role: req.user!.role,
    allowedClasses: req.user!.allowedClasses,
    allowedSubjects: req.user!.allowedSubjects,
    studentClassName: student.className,
    subject: subject.trim(),
  });
  if (!permission.allowed) {
    res.status(403).json({ error: permission.reason });
    return;
  }
  const grade = upsertGrade({
    studentId,
    term: term.trim(),
    subject: subject.trim(),
    marksObtained: obtained,
    maxMarks: max,
    remarks: remarks || '',
    gradedBy: req.user!.fullName,
  });
  logAudit(req.user!.id, req.user!.role, 'UPSERT_GRADE', grade.id);
  broadcastAll('grade:updated', grade);
  res.status(201).json({ grade });
});

// ================= ATTENDANCE =================

app.get('/api/attendance', requireAuth, (req, res) => {
  const user = req.user!;
  const allowed =
    user.role === 'admin' || user.role === 'teacher' ? undefined : user.linkedStudentIds;
  res.json({ attendance: listAttendance(allowed) });
});

app.post('/api/attendance/batch', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { entries } = req.body as {
    entries?: Array<{
      studentId: string;
      date: string;
      className: string;
      status: AttendanceStatus;
      note: string;
    }>;
  };
  if (!Array.isArray(entries) || entries.length === 0) {
    res.status(400).json({ error: 'Attendance entries are required.' });
    return;
  }
  const validStatuses = new Set(['Present', 'Absent', 'Late', 'Excused']);
  for (const e of entries) {
    if (!e.studentId || !e.date || !validStatuses.has(e.status)) {
      res.status(400).json({ error: 'Invalid attendance entry.' });
      return;
    }
  }
  saveAttendanceBatch(entries, req.user!.fullName);
  logAudit(req.user!.id, req.user!.role, 'MARK_ATTENDANCE_BATCH', entries[0].date);
  broadcastAll('attendance:updated', { date: entries[0].date, className: entries[0].className });
  res.json({ saved: entries.length });
});

// ================= STUDY NOTES =================

app.get('/api/notes', requireAuth, (_req, res) => {
  res.json({ notes: listNotes() });
});

app.post(
  '/api/notes',
  requireAuth,
  requireRole('admin', 'teacher'),
  upload.single('attachment'),
  (req, res) => {
    const { className, subject, title, content, dueDate } = req.body as {
      className?: string;
      subject?: string;
      title?: string;
      content?: string;
      dueDate?: string;
    };
    if (!className?.trim() || !subject?.trim() || !title?.trim() || !content?.trim()) {
      res.status(400).json({ error: 'Class, subject, title, and content are required.' });
      return;
    }
    let attachmentName: string | undefined;
    let attachmentFileId: string | undefined;
    if (req.file) {
      try {
        const meta = saveBufferSafely(req.file);
        attachmentName = meta.originalName;
        attachmentFileId = meta.fileId;
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
        return;
      }
    }
    const note = createNote({
      className: className.trim(),
      subject: subject.trim(),
      title: title.trim(),
      content: content.trim(),
      authorName: req.user!.fullName,
      authorId: req.user!.id,
      dueDate: dueDate?.trim() || undefined,
      attachmentName,
      attachmentFileId,
    });
    broadcastAll('note:created', note);
    res.status(201).json({ note });
  },
);

// ================= NOTICE BOARD =================

app.get('/api/notices', requireAuth, (req, res) => {
  const role = req.user!.role;
  const all = listNotices();
  const visible =
    role === 'admin' || role === 'teacher'
      ? all
      : all.filter(
          (n) =>
            n.audience === 'All' ||
            (role === 'student' && n.audience === 'Students') ||
            (role === 'parent' && n.audience === 'Parents'),
        );
  res.json({ notices: visible });
});

app.post('/api/notices', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { title, body, priority, audience, pinned } = req.body as {
    title?: string;
    body?: string;
    priority?: NoticePriority;
    audience?: 'All' | 'Students' | 'Parents' | 'Teachers';
    pinned?: boolean;
  };
  if (!title?.trim() || !body?.trim()) {
    res.status(400).json({ error: 'Notice title and body are required.' });
    return;
  }
  const notice = createNotice({
    title: title.trim(),
    body: body.trim(),
    priority: priority || 'General',
    audience: audience || 'All',
    pinned: Boolean(pinned),
    authorName: req.user!.fullName,
  });
  logAudit(req.user!.id, req.user!.role, 'PUBLISH_NOTICE', notice.id);
  broadcastAll('notice:created', notice);
  res.status(201).json({ notice });
});

app.delete('/api/notices/:id', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  deleteNotice(req.params.id);
  broadcastAll('notice:deleted', { id: req.params.id });
  res.json({ deleted: true });
});

// ================= AUTOMATED REPORT CARDS =================

app.get('/api/reports/:studentId', requireAuth, (req, res) => {
  const user = req.user!;
  const studentId = req.params.studentId;
  if (!canAccessStudent(user, studentId)) {
    res.status(403).json({ error: 'Access denied for this student report card.' });
    return;
  }
  const student = getStudentById(studentId, user.role === 'admin');
  if (!student) {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }
  const term = (req.query.term as string) || 'All Terms';
  const grades = listGrades([studentId]);
  const attendance = listAttendance([studentId]);
  const report = generateAutomatedReportCard(student, grades, attendance, term);
  res.json({ report });
});

// ================= REAL-TIME PARENT-TEACHER MESSAGING =================

app.get('/api/messages/contacts', requireAuth, (req, res) => {
  const user = req.user!;
  const users = listAllUsers().filter((u) => u.id !== user.id);

  // Also include virtual faculty/parent directory entries if demo users haven't been created yet
  const contacts = users.map((u) => ({
    id: u.id,
    fullName: u.fullName,
    role: u.role,
    subtitle:
      u.role === 'teacher'
        ? u.subjectSpecialty || 'Faculty'
        : u.role === 'parent'
        ? 'Parent / Guardian'
        : u.role === 'admin'
        ? 'School Administration'
        : 'Student',
    online: (userSockets.get(u.id)?.size || 0) > 0,
  }));

  res.json({ contacts });
});

app.get('/api/messages/thread/:peerId', requireAuth, (req, res) => {
  const me = req.user!.id;
  const peerId = req.params.peerId;
  const threadId = [me, peerId].sort().join('__');
  const all = listMessagesForUser(me).filter((m) => m.threadId === threadId);
  res.json({ threadId, messages: all });
});

app.post('/api/messages', requireAuth, (req, res) => {
  const sender = req.user!;
  const { recipientId, body, studentContext } = req.body as {
    recipientId?: string;
    body?: string;
    studentContext?: string;
  };
  if (!recipientId || !body?.trim()) {
    res.status(400).json({ error: 'Recipient and message text are required.' });
    return;
  }
  const recipient = findUserById(recipientId);
  if (!recipient) {
    res.status(404).json({ error: 'Recipient not found.' });
    return;
  }
  const threadId = [sender.id, recipient.id].sort().join('__');
  const message = saveChatMessage({
    threadId,
    senderId: sender.id,
    senderName: sender.fullName,
    senderRole: sender.role,
    recipientId: recipient.id,
    recipientName: recipient.fullName,
    body: body.trim(),
    studentContext: studentContext?.trim() || undefined,
  });

  broadcastToUsers([sender.id, recipient.id], 'chat:message', message);
  res.status(201).json({ message });
});

// ================= DIGITAL ADMISSIONS & DOCUMENT UPLOADS =================

app.post('/api/admissions/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: 'Please select a PDF, PNG, or JPEG document.' });
    return;
  }
  const docType = req.body?.docType as UploadedDocumentMeta['docType'];
  const validDocTypes = new Set([
    'Birth Certificate',
    'Previous Marksheet',
    'APAAR / Aadhaar Proof',
    'Transfer Certificate',
    'Applicant Photo',
  ]);
  if (!validDocTypes.has(docType)) {
    res.status(400).json({ error: 'Invalid document type.' });
    return;
  }
  try {
    const saved = saveBufferSafely(req.file);
    const document: UploadedDocumentMeta = {
      fileId: saved.fileId,
      docType,
      originalName: saved.originalName,
      mimeType: saved.mimeType,
      sizeBytes: saved.sizeBytes,
      uploadedAt: new Date().toISOString(),
    };
    res.status(201).json({ document });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

app.post('/api/admissions/apply', (req, res) => {
  const {
    studentName,
    fatherName,
    motherName,
    dob,
    applyingClass,
    previousSchool,
    previousMarksPercent,
    aaparId,
    aadharId,
    address,
    photoNumber,
    parentName,
    parentEmail,
    parentPhone,
    documents,
  } = req.body as {
    studentName?: string;
    fatherName?: string;
    motherName?: string;
    dob?: string;
    applyingClass?: string;
    previousSchool?: string;
    previousMarksPercent?: number;
    aaparId?: string;
    aadharId?: string;
    address?: string;
    photoNumber?: string;
    parentName?: string;
    parentEmail?: string;
    parentPhone?: string;
    documents?: UploadedDocumentMeta[];
  };

  if (
    !studentName?.trim() ||
    !fatherName?.trim() ||
    !motherName?.trim() ||
    !dob ||
    !applyingClass?.trim() ||
    !address?.trim() ||
    !parentPhone?.trim()
  ) {
    res.status(400).json({
      error:
        'Student Name, Father Name, Mother Name, Date of Birth, Applying Class, Address, and Phone Number are required.',
    });
    return;
  }

  const aaparCheck = validateTwelveDigitId(aaparId || '');
  const aadharCheck = validateTwelveDigitId(aadharId || '');
  if (!aaparCheck.valid || !aadharCheck.valid) {
    res.status(400).json({ error: 'APAAR ID and Aadhaar number must each be 12 numeric digits.' });
    return;
  }

  const docs = Array.isArray(documents) ? documents : [];
  const marksPct = Math.max(0, Math.min(100, Number(previousMarksPercent) || 0));

  const evaluation = evaluateAdmissionReadiness({
    aaparId: aaparCheck.digits,
    aadharId: aadharCheck.digits,
    previousMarksPercent: marksPct,
    documents: docs,
  });

  const now = new Date().toISOString();
  const refCode = `ADM-2026-${crypto.randomInt(1000, 9999)}`;
  const resolvedFather = fatherName.trim();
  const resolvedMother = motherName.trim();

  const application = createAdmissionApplication(refCode, evaluation.automatedStatus, {
    studentName: studentName.trim(),
    fatherName: resolvedFather,
    motherName: resolvedMother,
    dob,
    applyingClass: applyingClass.trim(),
    previousSchool: previousSchool?.trim() || 'N/A',
    previousMarksPercent: marksPct,
    aaparId: aaparCheck.digits,
    aadharId: aadharCheck.digits,
    address: address.trim(),
    photoNumber: photoNumber?.trim() || '',
    parentName: parentName?.trim() || resolvedFather,
    parentEmail: parentEmail?.trim().toLowerCase() || '',
    parentPhone: parentPhone.trim(),
    documents: docs,
    statusHistory: [
      {
        status: 'Submitted',
        note: 'Digital admission form submitted online.',
        timestamp: now,
        actor: 'Applicant Portal',
      },
      {
        status: evaluation.automatedStatus,
        note: evaluation.verificationNote,
        timestamp: now,
        actor: 'Automated Verification Engine',
      },
    ],
    reviewNotes: evaluation.verificationNote,
  });

  broadcastAll('admission:created', application);
  res.status(201).json({ application });
});

app.get('/api/admissions/track', (req, res) => {
  const refCode = String(req.query.refCode || '').trim();
  const contact = String(req.query.contact || req.query.email || '').trim();
  if (!refCode || !contact) {
    res.status(400).json({
      error: 'Provide both Application Reference Code and Phone Number or Email.',
    });
    return;
  }
  const application = findAdmissionByRefAndEmail(refCode, contact);
  if (!application) {
    res.status(404).json({ error: 'No matching admission application found.' });
    return;
  }
  res.json({ application });
});

app.get('/api/admissions', requireAuth, requireRole('admin'), (_req, res) => {
  res.json({ admissions: listAdmissions(false) });
});

app.patch('/api/admissions/:id/status', requireAuth, requireRole('admin'), (req, res) => {
  const { status, reviewNote } = req.body as {
    status?: AdmissionApplication['status'];
    reviewNote?: string;
  };
  const allowed = new Set<AdmissionApplication['status']>([
    'Under Review',
    'Approved',
    'Waitlisted',
    'Action Required',
    'Rejected',
  ]);
  if (!status || !allowed.has(status)) {
    res.status(400).json({ error: 'Invalid status update.' });
    return;
  }
  const result = updateAdmissionStatus({
    admissionId: req.params.id,
    nextStatus: status,
    reviewNote: reviewNote?.trim() || `Status updated to ${status}.`,
    actorName: req.user!.fullName,
  });
  if (!result) {
    res.status(404).json({ error: 'Admission application not found.' });
    return;
  }
  logAudit(req.user!.id, req.user!.role, `ADMISSION_${status.toUpperCase()}`, req.params.id);
  broadcastAll('admission:updated', result.application);
  res.json(result);
});

app.get('/api/files/:fileId', requireAuth, (req, res) => {
  const fileId = req.params.fileId;
  if (!/^[a-f0-9-]+$/.test(fileId)) {
    res.status(400).json({ error: 'Invalid file identifier.' });
    return;
  }
  const meta = uploadedFilesMeta.get(fileId);
  if (!meta) {
    res.status(404).json({ error: 'Uploaded file not found.' });
    return;
  }
  const resolved = path.resolve(UPLOADS_DIR, meta.storedName);
  if (!resolved.startsWith(UPLOADS_DIR + path.sep) || !fs.existsSync(resolved)) {
    res.status(404).json({ error: 'File no longer available on disk.' });
    return;
  }
  res.setHeader('Content-Type', meta.mimeType);
  res.setHeader('Content-Disposition', `inline; filename="${meta.originalName.replace(/"/g, '')}"`);
  res.sendFile(resolved);
});

// ================= USER ACCESS & AUDIT LOGS (ADMIN) =================

app.get('/api/users', requireAuth, requireRole('admin'), (_req, res) => {
  res.json({ users: listAllUsers() });
});

app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const {
    fullName,
    email,
    password,
    designation,
    role,
    linkedStudentIds,
    subjectSpecialty,
    allowedClasses,
    allowedSubjects,
  } = req.body as {
    fullName?: string;
    email?: string;
    password?: string;
    designation?: string;
    role?: UserRole;
    linkedStudentIds?: string[];
    subjectSpecialty?: string;
    allowedClasses?: string[];
    allowedSubjects?: string[];
  };
  if (!fullName?.trim() || !email?.trim() || !role) {
    res.status(400).json({ error: 'Full name, email, and role are required.' });
    return;
  }
  const effectivePassword =
    role === 'teacher'
      ? password?.trim() || generateTeacherDefaultPassword(fullName)
      : password || '';
  const minLen = role === 'teacher' ? 6 : 8;
  if (!effectivePassword || effectivePassword.length < minLen) {
    res.status(400).json({
      error:
        role === 'teacher'
          ? 'Teacher password must be at least 6 characters.'
          : 'Password must be at least 8 characters.',
    });
    return;
  }
  if (findUserByEmail(email)) {
    res.status(409).json({ error: 'An account with this email already exists.' });
    return;
  }
  const cleanClasses = Array.isArray(allowedClasses)
    ? Array.from(new Set(allowedClasses.map((c) => String(c).trim().toUpperCase()).filter(Boolean)))
    : [];
  const cleanSubjects = Array.isArray(allowedSubjects)
    ? Array.from(new Set(allowedSubjects.map((s) => String(s).trim()).filter(Boolean)))
    : [];

  const created = createUserAccount({
    fullName,
    email,
    password: effectivePassword,
    designation: designation?.trim() || undefined,
    role,
    linkedStudentIds: Array.isArray(linkedStudentIds) ? linkedStudentIds : [],
    subjectSpecialty: subjectSpecialty?.trim() || undefined,
    allowedClasses: role === 'teacher' ? cleanClasses : [],
    allowedSubjects: role === 'teacher' ? cleanSubjects : [],
  });
  logAudit(req.user!.id, req.user!.role, `CREATE_USER_${role.toUpperCase()}`, created.id);
  res.status(201).json({ user: created, assignedPassword: effectivePassword });
});

app.patch('/api/users/:id/permissions', requireAuth, requireRole('admin'), (req, res) => {
  const targetUser = findUserById(req.params.id);
  if (!targetUser) {
    res.status(404).json({ error: 'User account not found.' });
    return;
  }
  if (targetUser.role !== 'teacher') {
    res.status(400).json({ error: 'Class and subject grading permissions apply to Teacher accounts.' });
    return;
  }
  const { allowedClasses, allowedSubjects, subjectSpecialty, designation } = req.body as {
    allowedClasses?: string[];
    allowedSubjects?: string[];
    subjectSpecialty?: string;
    designation?: string;
  };
  const cleanClasses = Array.isArray(allowedClasses)
    ? Array.from(new Set(allowedClasses.map((c) => String(c).trim().toUpperCase()).filter(Boolean)))
    : [];
  const cleanSubjects = Array.isArray(allowedSubjects)
    ? Array.from(new Set(allowedSubjects.map((s) => String(s).trim()).filter(Boolean)))
    : [];

  const updated = updateUserPermissions(req.params.id, {
    allowedClasses: cleanClasses,
    allowedSubjects: cleanSubjects,
    subjectSpecialty: subjectSpecialty !== undefined ? subjectSpecialty.trim() : undefined,
    designation: designation !== undefined ? designation.trim() : undefined,
  });
  if (!updated) {
    res.status(404).json({ error: 'User account not found.' });
    return;
  }
  logAudit(req.user!.id, req.user!.role, 'UPDATE_TEACHER_PERMISSIONS', updated.id);
  broadcastToUsers([updated.id], 'user:permissions-updated', updated);
  res.json({ user: updated });
});

app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const targetId = req.params.id;
  if (targetId === req.user!.id) {
    res.status(400).json({ error: 'You cannot remove your own currently signed-in account.' });
    return;
  }
  const targetUser = findUserById(targetId);
  if (!targetUser) {
    res.status(404).json({ error: 'User account not found.' });
    return;
  }
  if (targetUser.role === 'admin') {
    const adminCount = listAllUsers().filter((u) => u.role === 'admin').length;
    if (adminCount <= 1) {
      res.status(400).json({ error: 'Cannot remove the last remaining Administrator account.' });
      return;
    }
  }
  deleteUserAccount(targetId);
  logAudit(req.user!.id, req.user!.role, `DELETE_USER_${targetUser.role.toUpperCase()}`, targetId);
  res.json({ deleted: true, id: targetId });
});

app.get('/api/audit-logs', requireAuth, requireRole('admin'), (_req, res) => {
  const logs = db
    .prepare('SELECT id, actor_id, actor_role, action, target_id, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 30')
    .all();
  res.json({ logs });
});

// ================= VITE / STATIC SPA ENTRY =================

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distDir, 'index.html'));
    });
  }

  const port = Number(process.env.PORT) || 3000;
  server.listen(port, '0.0.0.0', () => {
    console.log(`Pioneer Academy, Sonapur portal running on http://0.0.0.0:${port}`);
  });
}

startServer();
