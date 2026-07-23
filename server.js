/**
 * Halqa (حلقة) — Social Network Backend
 * Pure Node.js — no external dependencies required.
 * Data is stored in a local JSON file (data/db.json).
 *
 * Run:   node server.js
 * Env:   PORT (default 3000), JWT_SECRET (set a real secret in production)
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'halqa-dev-secret-change-me-in-production';
const DB_PATH = path.join(__dirname, 'data', 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_SIZE = 12 * 1024 * 1024; // 12MB (covers base64 images)

// ---------------------------------------------------------------------------
// Tiny "database" — JSON file, synchronous access (fine for small/medium apps)
// ---------------------------------------------------------------------------
function ensureDB() {
  if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  }
  if (!fs.existsSync(DB_PATH)) {
    const initial = {
      users: [
        {
          id: crypto.randomUUID(),
          username: 'admin',
          displayName: 'المشرف',
          email: 'admin@halqa.local',
          bio: 'حساب الإدارة الرئيسي',
          avatar: null,
          role: 'admin',
          verified: true,
          banned: false,
          following: [],
          followers: [],
          notifications: [],
          createdAt: new Date().toISOString(),
          ...hashPassword('admin123'),
        },
      ],
      posts: [],
      verifyRequests: [],
      reports: [],
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
  }
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check), Buffer.from(hash));
}

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signToken(payload) {
  const body = base64url(Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })));
  const sig = base64url(crypto.createHmac('sha256', SECRET).update(body).digest());
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = base64url(crypto.createHmac('sha256', SECRET).update(body).digest());
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    // token expiry: 30 days
    if (Date.now() - payload.iat > 30 * 24 * 60 * 60 * 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  const match = header.split(';').map((c) => c.trim()).find((c) => c.startsWith(name + '='));
  return match ? decodeURIComponent(match.split('=')[1]) : null;
}

function getUserFromReq(req, db) {
  const token = getCookie(req, 'halqa_token');
  const payload = verifyToken(token);
  if (!payload) return null;
  return db.users.find((u) => u.id === payload.uid) || null;
}

function publicUser(u) {
  if (!u) return null;
  const { hash, salt, email, ...safe } = u;
  return safe;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
function send(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...(extraHeaders || {}),
  });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        reject(new Error('BODY_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function saveBase64Image(dataUrl, prefix) {
  const match = /^data:(image\/(png|jpe?g|gif|webp));base64,(.+)$/.exec(dataUrl || '');
  if (!match) return null;
  const ext = match[2] === 'jpeg' ? 'jpg' : match[2];
  const buf = Buffer.from(match[3], 'base64');
  if (buf.length > 8 * 1024 * 1024) return null; // 8MB cap per image
  const filename = `${prefix}-${crypto.randomUUID()}.${ext}`;
  fs.writeFileSync(path.join(UPLOADS_DIR, filename), buf);
  return `/uploads/${filename}`;
}

function notify(db, username, notif) {
  const user = db.users.find((u) => u.username === username);
  if (!user) return;
  user.notifications.unshift({
    id: crypto.randomUUID(),
    read: false,
    createdAt: new Date().toISOString(),
    ...notif,
  });
  user.notifications = user.notifications.slice(0, 100);
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? '/index.html' : pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404 - غير موجود');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------
const routes = [];
function route(method, pattern, handler) {
  const paramNames = [];
  const regex = new RegExp(
    '^' +
      pattern.replace(/:[a-zA-Z]+/g, (m) => {
        paramNames.push(m.slice(1));
        return '([^/]+)';
      }) +
      '$'
  );
  routes.push({ method, regex, paramNames, handler });
}

async function handleApi(req, res, pathname, query) {
  for (const r of routes) {
    if (r.method !== req.method) continue;
    const m = r.regex.exec(pathname);
    if (!m) continue;
    const params = {};
    r.paramNames.forEach((name, i) => (params[name] = decodeURIComponent(m[i + 1])));
    try {
      let body = {};
      if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
        body = await parseBody(req);
      }
      return await r.handler(req, res, { params, query, body });
    } catch (err) {
      if (err.message === 'BODY_TOO_LARGE') return send(res, 413, { error: 'الملف كبير بزاف' });
      console.error(err);
      return send(res, 500, { error: 'خطأ فسيرفر' });
    }
  }
  send(res, 404, { error: 'المسار غير موجود' });
}

// ---------------------------------------------------------------------------
// AUTH ROUTES
// ---------------------------------------------------------------------------
route('POST', '/api/register', async (req, res, { body }) => {
  const db = readDB();
  const username = (body.username || '').trim().toLowerCase();
  const displayName = (body.displayName || '').trim();
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return send(res, 400, { error: 'اسم المستخدم خاصو يكون بين 3 و20 حرف (أحرف لاتينية، أرقام، _)' });
  }
  if (!displayName) return send(res, 400, { error: 'خاصك تدخل الاسم الكامل' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return send(res, 400, { error: 'البريد الإلكتروني ماشي صحيح' });
  if (password.length < 6) return send(res, 400, { error: 'كلمة السر خاصها تكون 6 حروف أو أكثر' });
  if (db.users.some((u) => u.username === username)) return send(res, 409, { error: 'اسم المستخدم مأخوذ' });
  if (db.users.some((u) => u.email === email)) return send(res, 409, { error: 'البريد الإلكتروني مسجل من قبل' });

  const user = {
    id: crypto.randomUUID(),
    username,
    displayName,
    email,
    bio: '',
    avatar: null,
    role: 'user',
    verified: false,
    banned: false,
    following: [],
    followers: [],
    notifications: [],
    createdAt: new Date().toISOString(),
    ...hashPassword(password),
  };
  db.users.push(user);
  writeDB(db);

  const token = signToken({ uid: user.id });
  send(res, 201, { user: publicUser(user) }, {
    'Set-Cookie': `halqa_token=${token}; HttpOnly; Path=/; Max-Age=${30 * 24 * 3600}; SameSite=Lax`,
  });
});

route('POST', '/api/login', async (req, res, { body }) => {
  const db = readDB();
  const identifier = (body.username || '').trim().toLowerCase();
  const password = body.password || '';
  const user = db.users.find((u) => u.username === identifier || u.email === identifier);
  if (!user || !verifyPassword(password, user.salt, user.hash)) {
    return send(res, 401, { error: 'اسم المستخدم أو كلمة السر غالطين' });
  }
  if (user.banned) return send(res, 403, { error: 'هاد الحساب محظور' });

  const token = signToken({ uid: user.id });
  send(res, 200, { user: publicUser(user) }, {
    'Set-Cookie': `halqa_token=${token}; HttpOnly; Path=/; Max-Age=${30 * 24 * 3600}; SameSite=Lax`,
  });
});

route('POST', '/api/logout', async (req, res) => {
  send(res, 200, { ok: true }, {
    'Set-Cookie': 'halqa_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax',
  });
});

route('GET', '/api/me', async (req, res) => {
  const db = readDB();
  const user = getUserFromReq(req, db);
  if (!user) return send(res, 401, { error: 'ماشي داخل' });
  send(res, 200, { user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// PROFILE ROUTES
// ---------------------------------------------------------------------------
route('GET', '/api/users/:username', async (req, res, { params }) => {
  const db = readDB();
  const target = db.users.find((u) => u.username === params.username);
  if (!target) return send(res, 404, { error: 'المستخدم غير موجود' });
  const posts = db.posts
    .filter((p) => p.authorUsername === target.username)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  send(res, 200, { user: publicUser(target), posts });
});

route('PUT', '/api/profile', async (req, res, { body }) => {
  const db = readDB();
  const user = getUserFromReq(req, db);
  if (!user) return send(res, 401, { error: 'ماشي داخل' });
  if (typeof body.displayName === 'string' && body.displayName.trim()) user.displayName = body.displayName.trim().slice(0, 60);
  if (typeof body.bio === 'string') user.bio = body.bio.slice(0, 250);
  if (typeof body.avatar === 'string' && body.avatar.startsWith('data:image/')) {
    const saved = saveBase64Image(body.avatar, 'avatar');
    if (saved) user.avatar = saved;
  }
  writeDB(db);
  send(res, 200, { user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// FOLLOW ROUTES
// ---------------------------------------------------------------------------
route('POST', '/api/follow/:username', async (req, res, { params }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const target = db.users.find((u) => u.username === params.username);
  if (!target || target.username === me.username) return send(res, 400, { error: 'طلب غير صحيح' });
  if (!me.following.includes(target.username)) me.following.push(target.username);
  if (!target.followers.includes(me.username)) target.followers.push(me.username);
  notify(db, target.username, { type: 'follow', from: me.username, message: `${me.displayName} بدا يتابعك` });
  writeDB(db);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/follow/:username', async (req, res, { params }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const target = db.users.find((u) => u.username === params.username);
  if (!target) return send(res, 404, { error: 'غير موجود' });
  me.following = me.following.filter((u) => u !== target.username);
  target.followers = target.followers.filter((u) => u !== me.username);
  writeDB(db);
  send(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// POSTS ROUTES
// ---------------------------------------------------------------------------
route('GET', '/api/posts', async (req, res, { query }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  let posts = db.posts.slice();
  if (query.scope === 'following' && me) {
    const set = new Set([...me.following, me.username]);
    posts = posts.filter((p) => set.has(p.authorUsername));
  }
  posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  posts = posts.slice(0, 50).map((p) => {
    const author = db.users.find((u) => u.username === p.authorUsername);
    return {
      ...p,
      authorDisplayName: author ? author.displayName : p.authorUsername,
      authorAvatar: author ? author.avatar : null,
      authorVerified: author ? author.verified : false,
      likeCount: p.likes.length,
      likedByMe: me ? p.likes.includes(me.username) : false,
      commentCount: p.comments.length,
    };
  });
  send(res, 200, { posts });
});

route('POST', '/api/posts', async (req, res, { body }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const content = (body.content || '').trim();
  if (!content && !body.image) return send(res, 400, { error: 'خاصك تكتب شي حاجة أو تزيد صورة' });
  if (content.length > 2000) return send(res, 400, { error: 'المنشور طويل بزاف' });

  let imagePath = null;
  if (typeof body.image === 'string' && body.image.startsWith('data:image/')) {
    imagePath = saveBase64Image(body.image, 'post');
  }

  const post = {
    id: crypto.randomUUID(),
    authorUsername: me.username,
    content,
    image: imagePath,
    likes: [],
    comments: [],
    createdAt: new Date().toISOString(),
  };
  db.posts.push(post);
  writeDB(db);
  send(res, 201, { post });
});

route('DELETE', '/api/posts/:id', async (req, res, { params }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return send(res, 404, { error: 'غير موجود' });
  if (post.authorUsername !== me.username && me.role !== 'admin') return send(res, 403, { error: 'ماعندكش الصلاحية' });
  db.posts = db.posts.filter((p) => p.id !== params.id);
  writeDB(db);
  send(res, 200, { ok: true });
});

route('POST', '/api/posts/:id/like', async (req, res, { params }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return send(res, 404, { error: 'غير موجود' });
  if (!post.likes.includes(me.username)) {
    post.likes.push(me.username);
    if (post.authorUsername !== me.username) {
      notify(db, post.authorUsername, { type: 'like', from: me.username, postId: post.id, message: `${me.displayName} عجبه منشورك` });
    }
  }
  writeDB(db);
  send(res, 200, { likeCount: post.likes.length });
});

route('DELETE', '/api/posts/:id/like', async (req, res, { params }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return send(res, 404, { error: 'غير موجود' });
  post.likes = post.likes.filter((u) => u !== me.username);
  writeDB(db);
  send(res, 200, { likeCount: post.likes.length });
});

route('POST', '/api/posts/:id/comments', async (req, res, { params, body }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return send(res, 404, { error: 'غير موجود' });
  const content = (body.content || '').trim();
  if (!content) return send(res, 400, { error: 'التعليق فارغ' });
  const comment = {
    id: crypto.randomUUID(),
    authorUsername: me.username,
    authorDisplayName: me.displayName,
    content: content.slice(0, 500),
    createdAt: new Date().toISOString(),
  };
  post.comments.push(comment);
  if (post.authorUsername !== me.username) {
    notify(db, post.authorUsername, { type: 'comment', from: me.username, postId: post.id, message: `${me.displayName} علق على منشورك` });
  }
  writeDB(db);
  send(res, 201, { comment });
});

// ---------------------------------------------------------------------------
// NOTIFICATIONS
// ---------------------------------------------------------------------------
route('GET', '/api/notifications', async (req, res) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  send(res, 200, { notifications: me.notifications });
});

route('POST', '/api/notifications/read', async (req, res) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  me.notifications.forEach((n) => (n.read = true));
  writeDB(db);
  send(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// VERIFICATION (blue badge) REQUESTS
// ---------------------------------------------------------------------------
route('POST', '/api/verify-request', async (req, res, { body }) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  if (me.verified) return send(res, 400, { error: 'الحساب متوثق ديجا' });
  const pending = db.verifyRequests.find((v) => v.username === me.username && v.status === 'pending');
  if (pending) return send(res, 400, { error: 'عندك طلب فالانتظار ديجا' });
  const reason = (body.reason || '').trim();
  if (!reason) return send(res, 400, { error: 'خاصك تكتب سبب الطلب' });

  let docImage = null;
  if (typeof body.document === 'string' && body.document.startsWith('data:image/')) {
    docImage = saveBase64Image(body.document, 'verifydoc');
  }

  const request = {
    id: crypto.randomUUID(),
    username: me.username,
    displayName: me.displayName,
    reason: reason.slice(0, 500),
    document: docImage,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  db.verifyRequests.push(request);
  writeDB(db);
  send(res, 201, { request });
});

route('GET', '/api/verify-request/mine', async (req, res) => {
  const db = readDB();
  const me = getUserFromReq(req, db);
  if (!me) return send(res, 401, { error: 'ماشي داخل' });
  const mine = db.verifyRequests.filter((v) => v.username === me.username).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  send(res, 200, { requests: mine });
});

// ---------------------------------------------------------------------------
// ADMIN ROUTES  (require role === 'admin')
// ---------------------------------------------------------------------------
function requireAdmin(req, db) {
  const user = getUserFromReq(req, db);
  if (!user || user.role !== 'admin') return null;
  return user;
}

route('GET', '/api/admin/stats', async (req, res) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  send(res, 200, {
    totalUsers: db.users.length,
    totalPosts: db.posts.length,
    verifiedUsers: db.users.filter((u) => u.verified).length,
    pendingVerifications: db.verifyRequests.filter((v) => v.status === 'pending').length,
    bannedUsers: db.users.filter((u) => u.banned).length,
  });
});

route('GET', '/api/admin/users', async (req, res, { query }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  let users = db.users.map(publicUser);
  if (query.q) {
    const q = query.q.toLowerCase();
    users = users.filter((u) => u.username.includes(q) || u.displayName.toLowerCase().includes(q));
  }
  send(res, 200, { users });
});

route('POST', '/api/admin/users/:id/ban', async (req, res, { params }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  const target = db.users.find((u) => u.id === params.id);
  if (!target) return send(res, 404, { error: 'غير موجود' });
  target.banned = true;
  writeDB(db);
  send(res, 200, { ok: true });
});

route('POST', '/api/admin/users/:id/unban', async (req, res, { params }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  const target = db.users.find((u) => u.id === params.id);
  if (!target) return send(res, 404, { error: 'غير موجود' });
  target.banned = false;
  writeDB(db);
  send(res, 200, { ok: true });
});

route('POST', '/api/admin/users/:id/make-admin', async (req, res, { params }) => {
  const db = readDB();
  const admin = requireAdmin(req, db);
  if (!admin) return send(res, 403, { error: 'ممنوع' });
  const target = db.users.find((u) => u.id === params.id);
  if (!target) return send(res, 404, { error: 'غير موجود' });
  target.role = 'admin';
  writeDB(db);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/admin/posts/:id', async (req, res, { params }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  db.posts = db.posts.filter((p) => p.id !== params.id);
  writeDB(db);
  send(res, 200, { ok: true });
});

route('GET', '/api/admin/verify-requests', async (req, res, { query }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  let reqs = db.verifyRequests.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  if (query.status) reqs = reqs.filter((r) => r.status === query.status);
  send(res, 200, { requests: reqs });
});

route('POST', '/api/admin/verify-requests/:id/approve', async (req, res, { params }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  const request = db.verifyRequests.find((r) => r.id === params.id);
  if (!request) return send(res, 404, { error: 'غير موجود' });
  request.status = 'approved';
  const user = db.users.find((u) => u.username === request.username);
  if (user) {
    user.verified = true;
    notify(db, user.username, { type: 'verified', message: 'مبروك! تقبل طلب التوثيق ديالك وحصلتي على الشارة الزرقاء ✔️' });
  }
  writeDB(db);
  send(res, 200, { ok: true });
});

route('POST', '/api/admin/verify-requests/:id/reject', async (req, res, { params, body }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  const request = db.verifyRequests.find((r) => r.id === params.id);
  if (!request) return send(res, 404, { error: 'غير موجود' });
  request.status = 'rejected';
  request.rejectReason = (body && body.reason) || '';
  const user = db.users.find((u) => u.username === request.username);
  if (user) {
    notify(db, user.username, { type: 'verify-rejected', message: 'تم رفض طلب التوثيق ديالك. تقدر تعاود تجرب من بعد.' });
  }
  writeDB(db);
  send(res, 200, { ok: true });
});

route('GET', '/api/admin/posts', async (req, res, { query }) => {
  const db = readDB();
  if (!requireAdmin(req, db)) return send(res, 403, { error: 'ممنوع' });
  let posts = db.posts.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  if (query.q) {
    const q = query.q.toLowerCase();
    posts = posts.filter((p) => p.content.toLowerCase().includes(q) || p.authorUsername.includes(q));
  }
  send(res, 200, { posts: posts.slice(0, 100) });
});

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
ensureDB();

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = decodeURIComponent(parsed.pathname);

  if (pathname.startsWith('/api/')) {
    return handleApi(req, res, pathname, parsed.query);
  }
  return serveStatic(req, res, pathname);
});

server.listen(PORT, () => {
  console.log(`✔ Halqa server running: http://localhost:${PORT}`);
  console.log(`  Admin login → username: admin / password: admin123 (بدلها فورا!)`);
});
