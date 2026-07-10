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
  const db = JSON.parse(Buffer.from(j.content, 'base64').toString('utf8'));
  return { db, sha: j.sha };
}

async function saveDb(db, sha, message) {
  const r = repo();
  const body = {
    message: message || 'taskdesk update',
    content: Buffer.from(JSON.stringify(db)).toString('base64'),
    branch: GH_BRANCH
  };
  if (sha) body.sha = sha;
  const res = await gh(`/repos/${r}/contents/${GH_PATH}`, { method: 'PUT', body: JSON.stringify(body) });
  if (res.status === 409 || res.status === 422) return false; // conflict -> caller retries
  if (!res.ok) throw new Error('GitHub write failed (' + res.status + '). Check GITHUB_TOKEN permissions.');
  return true;
}

/* ---------------- Helpers ---------------- */

const uid = () => crypto.randomBytes(8).toString('hex');
const now = () => new Date().toISOString();
const hash = (password, salt) => crypto.createHash('sha256').update(salt + '::' + password + '::' + SECRET).digest('hex');

function makeToken(userId) {
  const exp = Date.now() + TOKEN_TTL_HOURS * 3600 * 1000;
  const body = userId + '|' + exp;
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  return Buffer.from(body + '|' + sig).toString('base64');
}

function verifyToken(db, token) {
  if (!token) return null;
  try {
    const parts = Buffer.from(token, 'base64').toString('utf8').split('|');
    if (parts.length !== 3) return null;
    const body = parts[0] + '|' + parts[1];
    const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    if (sig !== parts[2]) return null;
    if (Date.now() > Number(parts[1])) return null;
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

/* ---------------- Actions (mutate db in place, return response) ---------------- */

function route(db, req) {
  const action = req.action;
  if (action === 'login') return login(db, req.payload);

  const user = verifyToken(db, req.token);
  if (!user) return { ok: false, error: 'AUTH', authFail: true };
  const p = req.payload || {};
  const adminOnly = () => user.role === 'admin' ? null : err('Admin only');

  switch (action) {
    case 'bootstrap': return { write: false, res: { ok: true, data: {
      me: publicUser(user),
      teams: db.teams,
      users: db.users.map(publicUser),
      tasks: db.tasks,
      timelogs: db.timelogs,
      comments: db.comments,
      activity: db.activity.slice(-500),
      notifications: db.notifications.filter(n => n.userId === user.id).slice(-100)
    }}};

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
      if (user.role === 'head' && p.team !== user.team) return err('Heads can only assign within their team');
      if (!p.title || !p.assignedTo || !p.dueDate) return err('Title, assignee and due date are required');
      const t = {
        id: uid(), title: p.title, description: p.description || '', priority: p.priority || 'Medium',
        team: p.team, assignedTo: p.assignedTo, assignedBy: user.id,
        startDate: p.startDate || '', dueDate: p.dueDate, estimatedHours: p.estimatedHours || '',
        project: p.project || '', category: p.category || 'Other',
        attachments: JSON.stringify(p.attachments || []), status: 'Pending', notes: p.notes || '',
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
      const editable = canManage(user, task)
        ? ['title','description','priority','team','assignedTo','startDate','dueDate','estimatedHours','project','category','attachments','notes','checklist','tags']
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
      const allowed = ['Pending','In Progress','On Hold','Under Review','Revision Required','Completed'];
      if (!allowed.includes(p.status)) return err('Invalid status');
      if (isAssignee && !canManage(user, task) && p.status === 'Completed') return err('Only your team head can mark tasks completed');
      task.status = p.status;
      task.updatedISO = now();
      if (p.status === 'Completed') task.completedISO = now();
      log(db, p.id, user.id, 'status', p.status);
      return { ok: true, data: task };
    }

    case 'submitTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (task.assignedTo !== user.id && !canManage(user, task)) return err('Not allowed');
      closeOpenLogs(db, p.id, user.id);
      task.status = 'Under Review';
      task.submittedISO = now();
      task.updatedISO = now();
      log(db, p.id, user.id, 'submitted', '');
      const head = db.users.find(u => u.role === 'head' && u.team === task.team && u.active);
      if (head) notify(db, head.id, 'review', p.id, user.name + ' submitted for review: ' + task.title);
      return { ok: true, data: task };
    }

    case 'reviewTask': {
      const task = db.tasks.find(t => t.id === p.id);
      if (!task) return err('Task not found');
      if (!canManage(user, task)) return err('Only team heads or admin can review');
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

function login(db, p) {
  if (!p || !p.email || !p.password) return err('Email and password required');
  const user = db.users.find(u => u.email === String(p.email).trim().toLowerCase());
  if (!user || !user.active) return err('Invalid credentials');
  if (hash(p.password, user.salt) !== user.passHash) return err('Invalid credentials');
  return { write: false, res: { ok: true, data: { token: makeToken(user.id), user: publicUser(user) } } };
}

const READ_ONLY = new Set(['login', 'bootstrap']);

/* ---------------- HTTP handler ---------------- */

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'POST only' });

  if (!process.env.GITHUB_TOKEN || !SECRET) {
    return res.status(200).json({ ok: false, error: 'Server not configured: add GITHUB_TOKEN and SECRET in Vercel > Settings > Environment Variables, then redeploy.' });
  }
  if (!repo()) {
    return res.status(200).json({ ok: false, error: 'Cannot determine GitHub repo: deploy this project from a GitHub repo, or set GH_REPO env var to "owner/repo".' });
  }

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
  if (!body || !body.action) return res.status(200).json({ ok: false, error: 'Bad request' });

  try {
    for (let attempt = 0; attempt < 4; attempt++) {
      let { db, sha } = await loadDb();
      let seeded = false;
      if (!db) { db = seedDb(); seeded = true; }

      const out = route(db, body);
      const response = out && out.res ? out.res : out;
      const isWrite = !(out && out.write === false) && !READ_ONLY.has(body.action);

      if (seeded || (isWrite && response.ok)) {
        const saved = await saveDb(db, sha, 'taskdesk: ' + body.action);
        if (!saved) { await new Promise(r => setTimeout(r, 150 + Math.random() * 250)); continue; } // conflict -> retry on fresh copy
      }
      return res.status(200).json(response);
    }
    return res.status(200).json({ ok: false, error: 'Storage busy, please retry' });
  } catch (e) {
    return res.status(200).json({ ok: false, error: String(e && e.message ? e.message : e) });
  }
};
