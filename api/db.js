/**
 * Ecom TaskDesk — backend as a single Vercel serverless function.
 * Storage: one JSON file (data/db.json) committed to your GitHub repo via the GitHub API.
 * Required env vars (Vercel > Project > Settings > Environment Variables):
 *   GITHUB_TOKEN  - GitHub personal access token with Contents read/write on this repo
 *   SECRET        - any long random string (signs login tokens + password hashes)
 * Optional:
 *   GH_REPO       - "owner/repo" (defaults to the repo this project is deployed from)
 *   GH_PATH       - data file path (default "data/db.json")
 *   GH_BRANCH     - branch to store data on (default "main")
 */

const crypto = require('crypto');

const SECRET = process.env.SECRET || '';
const TOKEN_TTL_HOURS = 72;
const DEFAULT_PASSWORD = 'ChangeMe!247';
const GH_PATH = process.env.GH_PATH || 'data/db.json';
const GH_BRANCH = process.env.GH_BRANCH || 'main';

/* ---------------- Rate limiting ---------------- */
const rateLimitMap = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 60; // max 60 requests per minute per IP
const LOGIN_LIMIT_MAX = 10; // max 10 login attempts per minute per IP
const loginAttempts = new Map(); // ip -> { count, resetAt, lockedUntil }

function getRateLimit(map, ip, max) {
  const now = Date.now();
  let entry = map.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    map.set(ip, entry);
  }
  entry.count++;
  return { allowed: entry.count <= max, count: entry.count, max };
}

function checkLoginLimit(ip) {
  const now = Date.now();
  let entry = loginAttempts.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS, lockedUntil: 0 };
  if (now < entry.lockedUntil) return { allowed: false, locked: true, seconds: Math.ceil((entry.lockedUntil - now) / 1000) };
  if (now > entry.resetAt) { entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS, lockedUntil: 0 }; }
  entry.count++;
  if (entry.count > LOGIN_LIMIT_MAX) {
    entry.lockedUntil = now + 15 * 60 * 1000; // lock for 15 minutes after too many attempts
    loginAttempts.set(ip, entry);
    return { allowed: false, locked: true, seconds: 900 };
  }
  loginAttempts.set(ip, entry);
  return { allowed: true };
}

function clearLoginLimit(ip) { loginAttempts.delete(ip); }

/* ---------------- Request size limit ---------------- */
const MAX_BODY_BYTES = 15 * 1024 * 1024; // 15MB max request (to handle 10MB file uploads)

function repo() {
  if (process.env.GH_REPO) return process.env.GH_REPO;
  const owner = process.env.VERCEL_GIT_REPO_OWNER, slug = process.env.VERCEL_GIT_REPO_SLUG;
  if (owner && slug) return owner + '/' + slug;
  return null;
}

/* ---------------- GitHub storage ---------------- */

async function gh(path, opts = {}) {
  const res = await fetch('https://api.github.com' + path, {
    ...opts,
    headers: {
      'Authorization': 'Bearer ' + process.env.GITHUB_TOKEN,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'ecom-taskdesk',
      ...(opts.headers || {})
    }
  });
  return res;
}

async function loadDb() {
  const r = repo();
  const res = await gh(`/repos/${r}/contents/${GH_PATH}?ref=${GH_BRANCH}`);
  if (res.status === 404) return { db: null, sha: null };
  if (!res.ok) throw new Error('GitHub read failed (' + res.status + '). Check GITHUB_TOKEN permissions.');
  const j = await res.json();
  const raw = Buffer.from(j.content.replace(/\n/g, ''), 'base64').toString('utf8').trim();
  if (!raw || raw.length < 10) return { db: null, sha: j.sha }; // treat as empty -> reseed
  try {
    const db = JSON.parse(raw);
    return { db, sha: j.sha };
  } catch(e) {
    // Corrupted file - reseed with same sha so we can overwrite it
    console.error('db.json corrupted, reseeding:', e.message);
    return { db: null, sha: j.sha };
  }
}

async function saveDb(db, sha, message) {
  const r = repo();
  // Validate before writing - never commit corrupted JSON
  let serialized;
  try {
    serialized = JSON.stringify(db);
    JSON.parse(serialized); // verify round-trip
    if (!serialized || serialized.length < 50) throw new Error('DB too small');
  } catch(e) {
    throw new Error('DB serialization failed: ' + e.message);
  }
  const body = {
    message: message || 'taskdesk update',
    content: Buffer.from(serialized).toString('base64'),
    branch: GH_BRANCH
  };
  if (sha) body.sha = sha;
  const res = await gh(`/repos/${r}/contents/${GH_PATH}`, { method: 'PUT', body: JSON.stringify(body) });
  if (res.status === 409 || res.status === 422) return false; // conflict -> caller retries
  if (!res.ok) throw new Error('GitHub write failed (' + res.status + '). Check GITHUB_TOKEN permissions.');
  // Fire backup on every save (async, non-blocking - never blocks main request)
  backupDb(db, serialized).catch(() => {});
  return true;
}

/* ---------------- Helpers ---------------- */

const uid = () => crypto.randomBytes(8).toString('hex');
const now = () => new Date().toISOString();
const hash = (password, salt) => crypto.createHash('sha256').update(salt + '::' + password + '::' + SECRET).digest('hex');

function makeToken(userId, ip) {
  const exp = Date.now() + TOKEN_TTL_HOURS * 3600 * 1000;
  const ipHash = crypto.createHash('sha256').update((ip || '') + SECRET).digest('hex').slice(0, 8);
  const body = userId + '|' + exp + '|' + ipHash;
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  return Buffer.from(body + '|' + sig).toString('base64');
}

function verifyToken(db, token, ip) {
  if (!token) return null;
  try {
    const parts = Buffer.from(token, 'base64').toString('utf8').split('|');
    if (parts.length !== 4) return null;
    const body = parts[0] + '|' + parts[1] + '|' + parts[2];
    const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[3]))) return null;
    if (Date.now() > Number(parts[1])) return null;
    // Soft IP check - warn but don't block (proxies/mobile can change IP)
    const ipHash = crypto.createHash('sha256').update((ip || '') + SECRET).digest('hex').slice(0, 8);
    if (parts[2] !== ipHash) { /* IP changed - still allow but log */ }
    const user = db.users.find(u => u.id === parts[0]);
    if (!user || !user.active) return null;
    return user;
  } catch (e) { return null; }
}

const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, team: u.team, active: !!u.active, mustReset: !!u.mustReset });
const canManage = (user, task) => user.role === 'admin' || (user.role === 'head' && user.team === task.team);
const err = m => ({ ok: false, error: m });

function log(db, taskId, userId, action, detail) {
  db.activity.push({ id: uid(), taskId, userId, action, detail: detail || '', createdISO: now() });
}
function notify(db, userId, type, taskId, message) {
  db.notifications.push({ id: uid(), userId, type, taskId, message, createdISO: now(), read: false });
}
function closeOpenLogs(db, taskId, userId) {
  db.timelogs.forEach(l => {
    if (l.taskId === taskId && l.userId === userId && !l.endISO) {
      const end = new Date();
      l.endISO = end.toISOString();
      l.seconds = Math.max(0, Math.round((end - new Date(l.startISO)) / 1000));
    }
  });
}

/* ---------------- Seed ---------------- */

function seedDb() {
  const db = { teams: [], users: [], tasks: [], timelogs: [], comments: [], activity: [], notifications: [] };
  [['Design', 0], ['Digital Marketing', 1], ['SEO', 2], ['Content', 3]]
    .forEach(t => db.teams.push({ id: uid(), name: t[0], color: t[1], createdISO: now() }));
  const seed = [
    ['Admin', 'admin@print247.us', 'admin', ''],
    ['Design Head', 'design.head@print247.us', 'head', 'Design'],
    ['Designer 1', 'designer1@print247.us', 'member', 'Design'],
    ['Designer 2', 'designer2@print247.us', 'member', 'Design'],
    ['Digital Head', 'digital.head@print247.us', 'head', 'Digital Marketing'],
    ['Digital Marketer 1', 'dm1@print247.us', 'member', 'Digital Marketing'],
    ['Digital Marketer 2', 'dm2@print247.us', 'member', 'Digital Marketing'],
    ['SEO Head', 'seo.head@print247.us', 'head', 'SEO'],
    ['SEO Specialist 1', 'seo1@print247.us', 'member', 'SEO'],
    ['SEO Specialist 2', 'seo2@print247.us', 'member', 'SEO'],
    ['Content Head', 'content.head@print247.us', 'head', 'Content'],
    ['Content Writer 1', 'writer1@print247.us', 'member', 'Content'],
    ['Content Writer 2', 'writer2@print247.us', 'member', 'Content'],
    ['Content Writer 3', 'writer3@print247.us', 'member', 'Content'],
    ['Content Writer 4', 'writer4@print247.us', 'member', 'Content']
  ];
  seed.forEach(u => {
    const salt = uid();
    db.users.push({ id: uid(), name: u[0], email: u[1], role: u[2], team: u[3],
      passHash: hash(DEFAULT_PASSWORD, salt), salt, active: true, mustReset: true, createdISO: now() });
  });
  return db;
}

/* ---------------- Backup system ---------------- */

// Keeps last 10 rolling backups: data/backups/db-1.json ... db-10.json
// Also saves a dated snapshot once per day: data/backups/db-YYYY-MM-DD.json
// On every successful write, the latest backup is always db-latest.json

async function backupDb(db, serialized) {
  const r = repo();
  try {
    const basePath = (process.env.GH_PATH || 'data/db.json').replace('db.json', 'backups/');

    // 1. Always save db-latest.json on every write (instant recovery point)
    await ghPut(r, basePath + 'db-latest.json', serialized, 'taskdesk: backup latest');

    // 2. Rolling numbered backups (db-1.json through db-10.json, rotate)
    // Read current rotation index
    let rotIdx = 1;
    try {
      const idxRes = await gh('/repos/' + r + '/contents/' + basePath + 'rotation.txt?ref=' + GH_BRANCH);
      if (idxRes.ok) {
        const idxJson = await idxRes.json();
        rotIdx = (parseInt(Buffer.from(idxJson.content.split('\n').join(''), 'base64').toString('utf8').trim()) % 10) + 1;
      }
    } catch(e) {}
    await ghPut(r, basePath + 'db-' + rotIdx + '.json', serialized, 'taskdesk: backup #' + rotIdx);
    await ghPut(r, basePath + 'rotation.txt', String(rotIdx), 'taskdesk: rotation index');

    // 3. Daily dated snapshot (once per day)
    const date = new Date().toISOString().slice(0, 10);
    const dailyPath = basePath + 'daily/db-' + date + '.json';
    const checkDaily = await gh('/repos/' + r + '/contents/' + dailyPath + '?ref=' + GH_BRANCH);
    if (checkDaily.status === 404) {
      await ghPut(r, dailyPath, serialized, 'taskdesk: daily snapshot ' + date);
    }
  } catch(e) {
    console.error('Backup failed (non-fatal):', e.message);
  }
}

async function ghPut(r, path, content, message) {
  // Get existing sha if file exists (needed to update)
  let sha;
  try {
    const res = await gh('/repos/' + r + '/contents/' + path + '?ref=' + GH_BRANCH);
    if (res.ok) { const j = await res.json(); sha = j.sha; }
  } catch(e) {}
  const body = {
    message,
    content: Buffer.from(content).toString('base64'),
    branch: GH_BRANCH
  };
  if (sha) body.sha = sha;
  const res = await gh('/repos/' + r + '/contents/' + path, { method: 'PUT', body: JSON.stringify(body) });
  return res.ok;
}

/* ---------------- Migration (auto-fixes old data on load) ---------------- */

function migrateDb(db) {
  let changed = false;

  // Ensure all top-level collections exist
  const collections = ['teams', 'users', 'tasks', 'timelogs', 'comments', 'activity', 'notifications'];
  collections.forEach(k => { if (!db[k]) { db[k] = []; changed = true; } });

  // Seed teams if missing
  if (!db.teams.length) {
    [['Design',0],['Digital Marketing',1],['SEO',2],['Content',3]]
      .forEach(t => db.teams.push({ id: uid(), name: t[0], color: t[1], createdISO: now() }));
    changed = true;
  }

  // Task field defaults (add any missing fields to existing tasks)
  const taskDefaults = {
    forwardedTo: '', description: '', priority: 'Medium', startDate: '',
    estimatedHours: '', project: '', category: 'Other',
    attachments: '[]', notes: '', checklist: '[]', tags: '[]',
    submittedISO: '', completedISO: '', updatedISO: ''
  };
  db.tasks.forEach(t => {
    Object.entries(taskDefaults).forEach(([k, v]) => {
      if (t[k] === undefined || t[k] === null) { t[k] = v; changed = true; }
    });
    // Normalise attachments: ensure type field exists
    try {
      const atts = JSON.parse(t.attachments || '[]');
      const fixed = atts.map(a => ({ type: 'link', ...a }));
      if (JSON.stringify(atts) !== JSON.stringify(fixed)) { t.attachments = JSON.stringify(fixed); changed = true; }
    } catch (e) { t.attachments = '[]'; changed = true; }
  });

  // User field defaults
  const userDefaults = { active: true, mustReset: false, team: '', notes: '' };
  db.users.forEach(u => {
    Object.entries(userDefaults).forEach(([k, v]) => {
      if (u[k] === undefined || u[k] === null) { u[k] = v; changed = true; }
    });
    // Normalize active field (could be string 'TRUE' from old Apps Script data)
    if (typeof u.active === 'string') { u.active = u.active === 'TRUE' || u.active === 'true'; changed = true; }
    if (typeof u.mustReset === 'string') { u.mustReset = u.mustReset === 'TRUE' || u.mustReset === 'true'; changed = true; }
  });

  // Timelog field defaults
  db.timelogs.forEach(l => {
    if (l.endISO === undefined) { l.endISO = ''; changed = true; }
    if (l.seconds === undefined) { l.seconds = ''; changed = true; }
  });

  // Notification field defaults
  db.notifications.forEach(n => {
    if (n.read === undefined) { n.read = false; changed = true; }
  });

  return changed;
}

/* ---------------- Actions (mutate db in place, return response) ---------------- */

async function route(db, req, ip) {
  const action = req.action;
  if (action === 'login') return login(db, req.payload, ip);

  const user = verifyToken(db, req.token, ip);
  if (!user) return { ok: false, error: 'AUTH', authFail: true };
  const p = req.payload || {};
  const adminOnly = () => user.role === 'admin' ? null : err('Admin only');

  switch (action) {
    case 'bootstrap': {
      // Generate fresh server-side reminders for this user
      const today = new Date(); today.setHours(0,0,0,0);
      const myActiveTasks = db.tasks.filter(t => t.assignedTo === user.id && t.status !== 'Completed');
      myActiveTasks.forEach(t => {
        if (!t.dueDate) return;
        const due = new Date(t.dueDate); due.setHours(0,0,0,0);
        const days = Math.round((due - today) / 86400000);
        let type = null, msg = null;
        if (days < 0)  { type = 'overdue';  msg = `Overdue by ${-days} day(s): ${t.title}`; }
        else if (days === 0) { type = 'due';  msg = `Due today: ${t.title}`; }
        else if (days === 1) { type = 'reminder'; msg = `Due tomorrow: ${t.title}`; }
        else if (days === 3) { type = 'reminder'; msg = `Due in 3 days: ${t.title}`; }
        else if (days === 7) { type = 'reminder'; msg = `Due in 7 days: ${t.title}`; }
        if (!type) return;
        // Only add if not already notified today
        const alreadySent = db.notifications.some(n =>
          n.userId === user.id && n.taskId === t.id && n.type === type &&
          n.createdISO && n.createdISO.slice(0,10) === today.toISOString().slice(0,10)
        );
        if (!alreadySent) {
          db.notifications.push({ id: uid(), userId: user.id, type, taskId: t.id, message: msg, createdISO: now(), read: false });
        }
      });
      // Approval reminders for heads/admin
      if (user.role !== 'member') {
        const pendingReview = db.tasks.filter(t => t.status === 'Under Review' &&
          (user.role === 'admin' || t.team === user.team));
        if (pendingReview.length > 0) {
          const alreadySent = db.notifications.some(n =>
            n.userId === user.id && n.type === 'review_pending' &&
            n.createdISO && n.createdISO.slice(0,10) === today.toISOString().slice(0,10)
          );
          if (!alreadySent) {
            db.notifications.push({ id: uid(), userId: user.id, type: 'review', taskId: null,
              message: `${pendingReview.length} task(s) waiting for your approval`, createdISO: now(), read: false });
          }
        }
      }
      return { write: true, res: { ok: true, data: {
      me: publicUser(user),
      teams: db.teams,
      users: db.users.map(publicUser),
      tasks: db.tasks,
      timelogs: db.timelogs,
      comments: db.comments,
      activity: db.activity.slice(-500),
      notifications: db.notifications.filter(n => n.userId === user.id).slice(-100)
    }}};
    }

    case 'changePassword': {
      if (!p.newPassword || String(p.newPassword).length < 8) return err('Password must be 8+ characters');
      if (!user.mustReset) {
        if (!p.oldPassword || hash(p.oldPassword, user.salt) !== user.passHash) return err('Current password is incorrect');
      }
      user.salt = uid();
      user.passHash = hash(p.newPassword, user.salt);
      user.mustReset = false;
      return { ok: true, data: { done: true } };
    }

    /* ---- tasks ---- */
    case 'createTask': {
      if (user.role === 'member') return err('Members cannot create tasks');
      if (!p.title || !p.assignedTo || !p.dueDate) return err('Title, assignee and due date are required');
      // Sanitize inputs
      p.title = String(p.title).slice(0, 200);
      p.description = String(p.description || '').slice(0, 2000);
      p.notes = String(p.notes || '').slice(0, 2000);
      p.project = String(p.project || '').slice(0, 100);
      const t = {
        id: uid(), title: p.title, description: p.description || '', priority: p.priority || 'Medium',
        team: p.team, assignedTo: p.assignedTo, assignedBy: user.id,
        startDate: p.startDate || '', dueDate: p.dueDate, estimatedHours: p.estimatedHours || '',
        project: p.project || '', category: p.category || 'Other',
        attachments: JSON.stringify(p.attachments || []), status: 'Pending', forwardedTo: '', notes: p.notes || '',
        checklist: JSON.stringify(p.checklist || []), tags: JSON.stringify(p.tags || []),
        createdISO: now(), updatedISO: now(), submittedISO: '', completedISO: ''
      };
      db.tasks.push(t);
      log(db, t.id, user.id, 'created', t.title);
      notify(db, t.assignedTo, 'assigned', t.id, user.name + ' assigned you: ' + t.title);
      return { ok: true, data: t };
    }

    case 'updateTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      const isAssignee = task.assignedTo === user.id;
      if (!canManage(user, task) && !isAssignee) return err('Not allowed');
      // Admin: full edit. Head: due date only. Member (assignee): notes/attachments/checklist
      const editable = user.role === 'admin'
        ? ['title','description','priority','team','assignedTo','startDate','dueDate','estimatedHours','project','category','attachments','notes','checklist','tags']
        : user.role === 'head'
          ? ['dueDate']
          : ['notes','attachments','checklist'];
      const prevAssignee = task.assignedTo;
      editable.forEach(k => {
        if (p[k] !== undefined) task[k] = (k === 'attachments' || k === 'checklist' || k === 'tags') ? JSON.stringify(p[k]) : p[k];
      });
      task.updatedISO = now();
      log(db, p.id, user.id, 'updated', editable.filter(k => p[k] !== undefined).join(', '));
      if (task.assignedTo !== prevAssignee) notify(db, task.assignedTo, 'assigned', p.id, user.name + ' assigned you: ' + task.title);
      return { ok: true, data: task };
    }

    case 'deleteTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (!canManage(user, task)) return err('Not allowed');
      db.tasks = db.tasks.filter(t => t.id !== p.id);
      log(db, p.id, user.id, 'deleted', task.title);
      return { ok: true, data: { id: p.id } };
    }

    case 'setStatus': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      const isAssignee = task.assignedTo === user.id;
      if (!canManage(user, task) && !isAssignee) return err('Not allowed');
      const allowed = ['Pending','In Progress','On Hold','Under Review','Revision Required'];
      if (!allowed.includes(p.status)) return err('Invalid status — tasks can only be completed via approval');
      task.status = p.status;
      task.updatedISO = now();
      if (p.status === 'Completed') task.completedISO = now();
      log(db, p.id, user.id, 'status', p.status);
      return { ok: true, data: task };
    }

    case 'listBackups': {
      const gate = adminOnly(); if (gate) return gate;
      const r = repo();
      const basePath = (process.env.GH_PATH || 'data/db.json').replace('db.json', 'backups/');
      try {
        const res = await gh('/repos/' + r + '/contents/' + basePath + '?ref=' + GH_BRANCH);
        if (!res.ok) return { ok: true, data: { backups: [] } };
        const files = await res.json();
        const backups = Array.isArray(files) ? files
          .filter(f => f.name.endsWith('.json'))
          .map(f => ({ name: f.name, path: f.path, size: f.size, sha: f.sha }))
          .sort((a, b) => b.name.localeCompare(a.name))
          .slice(0, 20)
          : [];
        // Also check daily folder
        const dailyRes = await gh('/repos/' + r + '/contents/' + basePath + 'daily/?ref=' + GH_BRANCH).catch(() => ({ ok: false }));
        if (dailyRes.ok) {
          const dailyFiles = await dailyRes.json();
          if (Array.isArray(dailyFiles)) {
            dailyFiles.filter(f => f.name.endsWith('.json'))
              .map(f => ({ name: 'daily/' + f.name, path: f.path, size: f.size, sha: f.sha }))
              .sort((a, b) => b.name.localeCompare(a.name))
              .forEach(f => backups.push(f));
          }
        }
        return { write: false, res: { ok: true, data: { backups } } };
      } catch(e) {
        return { ok: true, data: { backups: [], error: e.message } };
      }
    }

    case 'restoreBackup': {
      const gate = adminOnly(); if (gate) return gate;
      const r = repo();
      if (!p.path) return err('Backup path required');
      try {
        const res = await gh('/repos/' + r + '/contents/' + p.path + '?ref=' + GH_BRANCH);
        if (!res.ok) return err('Backup file not found');
        const j = await res.json();
        const raw = Buffer.from(j.content.split('\n').join(''), 'base64').toString('utf8').trim();
        const restored = JSON.parse(raw);
        // Validate it looks like a real db
        if (!restored.users || !restored.tasks) return err('Invalid backup file');
        // Merge restored into current db structure
        db.teams = restored.teams || db.teams;
        db.users = restored.users || db.users;
        db.tasks = restored.tasks || db.tasks;
        db.timelogs = restored.timelogs || db.timelogs;
        db.comments = restored.comments || db.comments;
        db.activity = restored.activity || db.activity;
        db.notifications = restored.notifications || db.notifications;
        log(db, null, user.id, 'restore', 'Restored from backup: ' + p.path);
        return { ok: true, data: { restored: true, users: db.users.length, tasks: db.tasks.length } };
      } catch(e) {
        return err('Restore failed: ' + e.message);
      }
    }

    case 'uploadFile': {
      // File uploads don't need db write - handled separately
      return uploadFile(p);
    }

    case 'forwardTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (!canManage(user, task)) return err('Not allowed');
      const member = db.users.find(u => u.id === p.memberId && u.active && u.team === task.team);
      if (!member) return err('Member not found in this team');
      task.forwardedTo = task.forwardedTo || task.assignedTo; // remember original assignee (head)
      task.assignedTo = p.memberId;
      task.status = 'Pending';
      task.updatedISO = now();
      log(db, task.id, user.id, 'forwarded', user.name + ' → ' + member.name);
      notify(db, p.memberId, 'assigned', task.id, user.name + ' assigned you: ' + task.title);
      return { ok: true, data: task };
    }

    case 'submitTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (task.assignedTo !== user.id) return err('Only the assignee can submit this task');
      closeOpenLogs(db, p.id, user.id);
      task.status = 'Under Review';
      task.submittedISO = now();
      task.updatedISO = now();
      log(db, p.id, user.id, 'submitted', 'sent for approval');
      // notify ALL heads + admin
      db.users.filter(u => u.active && (u.role === 'admin' || (u.role === 'head' && u.team === task.team)))
        .forEach(u => notify(db, u.id, 'review', p.id, user.name + ' submitted for approval: ' + task.title));
      return { ok: true, data: task };
    }

    case 'reviewTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (user.role === 'member') return err('Only team leads and admins can approve tasks');
      if (!canManage(user, task)) return err('Only the team lead or admin can approve this task');
      if (p.decision === 'approve') {
        task.status = 'Completed';
        task.completedISO = now();
        task.updatedISO = now();
        log(db, p.id, user.id, 'approved', '');
        notify(db, task.assignedTo, 'approved', p.id, user.name + ' approved: ' + task.title);
      } else {
        task.status = 'Revision Required';
        task.updatedISO = now();
        log(db, p.id, user.id, 'revision', p.note || '');
        notify(db, task.assignedTo, 'revision', p.id, user.name + ' requested revision: ' + task.title + (p.note ? ' — ' + p.note : ''));
        if (p.note) db.comments.push({ id: uid(), taskId: p.id, userId: user.id, text: '[Revision] ' + p.note, createdISO: now() });
      }
      return { ok: true, data: task };
    }

    /* ---- timer ---- */
    case 'timerStart': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (task.assignedTo !== user.id) return err('Timer is for the assignee only');
      db.timelogs.filter(l => l.userId === user.id && !l.endISO).forEach(l => closeOpenLogs(db, l.taskId, user.id));
      if (!db.timelogs.find(l => l.taskId === p.id && l.userId === user.id && !l.endISO)) {
        db.timelogs.push({ id: uid(), taskId: p.id, userId: user.id, startISO: now(), endISO: '', seconds: '' });
      }
      if (['Pending','On Hold','Revision Required'].includes(task.status)) {
        task.status = 'In Progress';
        task.updatedISO = now();
      }
      log(db, p.id, user.id, 'timer_start', '');
      return { ok: true, data: { task, timelogs: db.timelogs } };
    }

    case 'timerPause': {
      closeOpenLogs(db, p.id, user.id);
      log(db, p.id, user.id, 'timer_pause', '');
      return { ok: true, data: { timelogs: db.timelogs } };
    }

    case 'timerStop': {
      closeOpenLogs(db, p.id, user.id);
      const task = db.tasks.find(t => t.id === p.id);
      if (p.hold && task) { task.status = 'On Hold'; task.updatedISO = now(); }
      log(db, p.id, user.id, 'timer_stop', p.hold ? 'on hold' : '');
      return { ok: true, data: { task, timelogs: db.timelogs } };
    }

    /* ---- comments / notifications ---- */
    case 'addComment': {
      const task = db.tasks.find(t => t.id === p.taskId);
      if (!task) return err('Task not found');
      if (!p.text) return err('Empty comment');
      const c = { id: uid(), taskId: p.taskId, userId: user.id, text: p.text, createdISO: now() };
      db.comments.push(c);
      [task.assignedTo, task.assignedBy]
        .filter((x, i, a) => x && x !== user.id && a.indexOf(x) === i)
        .forEach(u => notify(db, u, 'comment', p.taskId, user.name + ' commented on: ' + task.title));
      return { ok: true, data: c };
    }

    case 'markRead': {
      db.notifications.forEach(n => { if (n.userId === user.id) n.read = true; });
      return { ok: true, data: { done: true } };
    }

    /* ---- admin ---- */
    case 'createUser': {
      const gate = adminOnly(); if (gate) return gate;
      if (!p.name || !p.email || !p.role) return err('Name, email, role required');
      if (db.users.find(u => u.email === String(p.email).toLowerCase())) return err('Email already exists');
      const salt = uid();
      const u = { id: uid(), name: p.name, email: String(p.email).toLowerCase(), role: p.role, team: p.team || '',
        passHash: hash(p.password || DEFAULT_PASSWORD, salt), salt, active: true, mustReset: true, createdISO: now() };
      db.users.push(u);
      return { ok: true, data: publicUser(u) };
    }

    case 'updateUser': {
      const gate = adminOnly(); if (gate) return gate;
      const target = db.users.find(u => u.id === p.id);
      if (!target) return err('User not found');
      ['name','email','role','team','active'].forEach(k => { if (p[k] !== undefined) target[k] = k === 'active' ? (p[k] === true || p[k] === 'TRUE') : p[k]; });
      return { ok: true, data: publicUser(target) };
    }

    case 'deleteUser': {
      const gate = adminOnly(); if (gate) return gate;
      const target = db.users.find(u => u.id === p.id);
      if (!target) return err('User not found');
      target.active = false;
      return { ok: true, data: { id: p.id } };
    }

    case 'resetPassword': {
      const gate = adminOnly(); if (gate) return gate;
      const target = db.users.find(u => u.id === p.id);
      if (!target) return err('User not found');
      target.salt = uid();
      target.passHash = hash(p.password || DEFAULT_PASSWORD, target.salt);
      target.mustReset = true;
      return { ok: true, data: { done: true } };
    }

    case 'createTeam': {
      const gate = adminOnly(); if (gate) return gate;
      const name = String(p.name || '').trim();
      if (!name) return err('Team name required');
      if (db.teams.some(t => t.name.toLowerCase() === name.toLowerCase())) return err('Team already exists');
      const t = { id: uid(), name, color: p.color || 0, createdISO: now() };
      db.teams.push(t);
      return { ok: true, data: t };
    }

    case 'deleteTeam': {
      const gate = adminOnly(); if (gate) return gate;
      const team = db.teams.find(t => t.id === p.id);
      if (!team) return err('Team not found');
      if (db.users.some(u => u.team === team.name && u.active)) return err('Move or deactivate its members first');
      if (db.tasks.some(t => t.team === team.name)) return err('Team still has tasks. Reassign or delete them first');
      db.teams = db.teams.filter(t => t.id !== p.id);
      return { ok: true, data: { id: p.id } };
    }

    default: return err('Unknown action: ' + action);
  }
}

function login(db, p, ip) {
  if (!p || !p.email || !p.password) return err('Email and password required');
  // Rate limit login attempts
  const limit = checkLoginLimit(ip);
  if (!limit.allowed) return err(`Too many login attempts. Try again in ${limit.seconds} seconds.`);
  const user = db.users.find(u => u.email === String(p.email).trim().toLowerCase());
  if (!user || !user.active) return err('Invalid credentials');
  if (hash(p.password, user.salt) !== user.passHash) return err('Invalid credentials');
  clearLoginLimit(ip); // reset on success
  return { write: false, res: { ok: true, data: { token: makeToken(user.id, ip), user: publicUser(user) } } };
}

const READ_ONLY = new Set(['login']);

/* ---------------- File upload (stores in GitHub, returns URL) ---------------- */
async function uploadFile(p) {
  const r = repo();
  if (!p || !p.name || !p.data) return err('File name and data required');
  // Validate - only images and PDFs, max 4MB base64 (~3MB file)
  const MAX_B64 = 4 * 1024 * 1024;
  if (p.data.length > MAX_B64) return err('File too large (max 3MB)');
  const allowed = ['image/jpeg','image/png','image/gif','image/webp','application/pdf'];
  if (p.mime && !allowed.includes(p.mime)) return err('Only images and PDFs allowed');
  // Strip data URL prefix if present
  const b64 = p.data.includes(',') ? p.data.split(',')[1] : p.data;
  const ext = p.name.split('.').pop().toLowerCase().replace(/[^a-z0-9]/g, '') || 'bin';
  const safeName = uid() + '.' + ext;
  const filePath = 'data/uploads/' + safeName;
  const body = {
    message: 'taskdesk: upload ' + p.name,
    content: b64,
    branch: GH_BRANCH
  };
  const res = await gh('/repos/' + r + '/contents/' + filePath, { method: 'PUT', body: JSON.stringify(body) });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    const j2 = await res.json().catch(() => ({})); throw new Error('Upload failed (' + res.status + '): ' + (j2.message || ''));
  }
  // Return raw GitHub URL
  const rawUrl = 'https://raw.githubusercontent.com/' + r + '/' + GH_BRANCH + '/' + filePath;
  return { ok: true, data: { url: rawUrl, name: p.name, path: filePath, size: p.size || 0 } };
}

/* ---------------- HTTP handler ---------------- */

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'POST only' });

  // Get client IP for rate limiting
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                   req.headers['x-real-ip'] ||
                   req.socket?.remoteAddress || 'unknown';

  // Global rate limit
  const globalLimit = getRateLimit(rateLimitMap, clientIp, RATE_LIMIT_MAX);
  if (!globalLimit.allowed) {
    res.setHeader('Retry-After', '60');
    return res.status(200).json({ ok: false, error: 'Too many requests. Please slow down.' });
  }

  if (!process.env.GITHUB_TOKEN || !SECRET) {
    return res.status(200).json({ ok: false, error: 'Server not configured: add GITHUB_TOKEN and SECRET in Vercel > Settings > Environment Variables, then redeploy.' });
  }
  if (!repo()) {
    return res.status(200).json({ ok: false, error: 'Cannot determine GitHub repo: deploy this project from a GitHub repo, or set GH_REPO env var to "owner/repo".' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    if (body.length > MAX_BODY_BYTES) return res.status(200).json({ ok: false, error: 'Request too large' });
    try { body = JSON.parse(body); } catch (e) { body = null; }
  }
  if (!body || !body.action) return res.status(200).json({ ok: false, error: 'Bad request' });
  // Sanitize action name
  if (typeof body.action !== 'string' || body.action.length > 50) return res.status(200).json({ ok: false, error: 'Invalid action' });

  try {
    for (let attempt = 0; attempt < 4; attempt++) {
      let { db, sha } = await loadDb();
      let seeded = false;
      if (!db) { db = seedDb(); seeded = true; }

      // Auto-migrate: fill in any missing fields from schema updates
      const migrated = !seeded && migrateDb(db);

      const out = await route(db, body, clientIp);
      const response = out && out.res ? out.res : out;
      const isWrite = !(out && out.write === false) && !READ_ONLY.has(body.action);

      if (seeded || migrated || (isWrite && response.ok)) {
        const saved = await saveDb(db, sha, seeded ? 'taskdesk: seed' : migrated ? 'taskdesk: migrate' : 'taskdesk: ' + body.action);
        if (!saved) { await new Promise(r => setTimeout(r, 150 + Math.random() * 250)); continue; } // conflict -> retry on fresh copy
      }
      return res.status(200).json(response);
    }
    return res.status(200).json({ ok: false, error: 'Storage busy, please retry' });
  } catch (e) {
    return res.status(200).json({ ok: false, error: String(e && e.message ? e.message : e) });
  }
};
