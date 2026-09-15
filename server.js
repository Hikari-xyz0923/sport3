const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const port = Number(process.argv[2] || process.env.PORT || 8080);
const defaultHost = process.env.HOST || '127.0.0.1';
const os = require('os');
const dataDir = process.env.SPORT_BUDDY_DATA_DIR || path.join(os.tmpdir(), 'zhidonghu_data');
const dbFile = path.join(dataDir, 'data.json');
const sessions = new Map();
const secureCookies = process.env.COOKIE_SECURE === 'true' || (process.env.NODE_ENV === 'production' && process.env.COOKIE_SECURE !== 'false');
const mime = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon'
};

function emptyDb() { return { users: [], profiles: [], posts: [], matches: [], messages: [], activities: [] }; }
function readDb() { try { const db = JSON.parse(fs.readFileSync(dbFile, 'utf8')); for (const key of ['users', 'profiles', 'posts', 'matches', 'messages', 'activities']) if (!Array.isArray(db[key])) db[key] = []; return db; } catch { return emptyDb(); } }
function writeDb(db) { fs.mkdirSync(dataDir, { recursive: true }); fs.writeFileSync(dbFile, JSON.stringify(db, null, 2), 'utf8'); }
function id(prefix) { return `${prefix}_${crypto.randomBytes(8).toString('hex')}`; }
function hash(password, salt = crypto.randomBytes(16).toString('hex')) { return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`; }
function verify(password, stored) { const [salt, digest] = String(stored).split(':'); if (!salt || !digest) return false; const actual = crypto.scryptSync(password, salt, 64).toString('hex'); return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(digest)); }
function body(req) { return new Promise((resolve, reject) => { let raw = ''; req.on('data', chunk => { raw += chunk; if (raw.length > 1e6) req.destroy(); }); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('请求数据格式错误')); } }); req.on('error', reject); }); }
function send(res, status, payload) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(payload)); }
function setSessionCookie(res, token) { res.setHeader('Set-Cookie', `sb_token=${token}; HttpOnly; SameSite=Lax; Path=/${secureCookies ? '; Secure' : ''}`); }
function currentUser(req) { const token = req.headers.cookie?.match(/sb_token=([^;]+)/)?.[1]; return token ? sessions.get(token) : null; }
function publicProfile(db, profile) { const user = db.users.find(x => x.id === profile.userId); if (!user) return null; return { ...profile, username: user.username, joinedAt: user.createdAt }; }
function safeUser(db, userId) { const user = db.users.find(x => x.id === userId); if (!user) return null; const profile = db.profiles.find(x => x.userId === userId) || { userId, name: user.username, area: '', sports: [], times: '', tags: [], verified: false }; return { id: user.id, username: user.username, createdAt: user.createdAt, profile: publicProfile(db, profile) }; }

async function api(req, res, pathname) {
  let db = readDb();
  if (pathname === '/api/me' && req.method === 'GET') { const uid = currentUser(req); return send(res, 200, { user: uid ? safeUser(db, uid) : null }); }
  if (pathname === '/api/register' && req.method === 'POST') {
    const data = await body(req); db = readDb(); const username = String(data.username || '').trim(); const password = String(data.password || '');
    if (username.length < 2 || password.length < 6) return send(res, 400, { error: '用户名至少 2 个字符，密码至少 6 位' });
    if (db.users.some(x => x.username.toLowerCase() === username.toLowerCase())) return send(res, 409, { error: '用户名已存在，请换一个' });
    const user = { id: id('u'), username, passwordHash: hash(password), createdAt: new Date().toISOString() };
    db.users.push(user); db.profiles.push({ userId: user.id, name: String(data.name || username).trim() || username, area: String(data.area || '海淀区').trim(), sports: Array.isArray(data.sports) ? data.sports.slice(0, 5) : [], times: String(data.times || ''), tags: [], verified: false }); writeDb(db);
    const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, user.id); setSessionCookie(res, token); return send(res, 201, { user: safeUser(db, user.id) });
  }
  if (pathname === '/api/login' && req.method === 'POST') {
    const data = await body(req); const user = db.users.find(x => x.username.toLowerCase() === String(data.username || '').trim().toLowerCase());
    if (!user || !verify(String(data.password || ''), user.passwordHash)) return send(res, 401, { error: '用户名或密码不正确' });
    const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, user.id); setSessionCookie(res, token); return send(res, 200, { user: safeUser(db, user.id) });
  }
  if (pathname === '/api/logout' && req.method === 'POST') { const token = req.headers.cookie?.match(/sb_token=([^;]+)/)?.[1]; if (token) sessions.delete(token); res.setHeader('Set-Cookie', `sb_token=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/${secureCookies ? '; Secure' : ''}`); return send(res, 200, { ok: true }); }
  const uid = currentUser(req); if (!uid) return send(res, 401, { error: '请先登录' });
  if (pathname === '/api/buddies' && req.method === 'GET') { const q = new URL(req.url, `http://${req.headers.host}`).searchParams; const sport = q.get('sport') || ''; const level = q.get('level') || ''; const search = (q.get('search') || '').toLowerCase(); let list = db.profiles.filter(p => p.userId !== uid).map(p => publicProfile(db, p)).filter(Boolean); if (sport) list = list.filter(p => (p.sports || []).some(x => x.includes(sport))); if (level) list = list.filter(p => (p.sports || []).some(x => x.includes(level))); if (search) list = list.filter(p => `${p.name}${p.area}${(p.sports || []).join('')}`.toLowerCase().includes(search)); if (q.get('shuffle') === '1') list.sort(() => Math.random() - .5); return send(res, 200, { buddies: list }); }
  if (pathname === '/api/profile' && req.method === 'PUT') { const data = await body(req); db = readDb(); let profile = db.profiles.find(p => p.userId === uid); if (!profile) { profile = { userId: uid }; db.profiles.push(profile); } for (const key of ['name', 'area', 'times']) if (data[key] !== undefined) profile[key] = String(data[key]).trim(); if (Array.isArray(data.sports)) profile.sports = data.sports.slice(0, 5).map(String); if (Array.isArray(data.tags)) profile.tags = data.tags.slice(0, 5).map(String); writeDb(db); return send(res, 200, { user: safeUser(db, uid) }); }
  if (pathname === '/api/posts' && req.method === 'GET') return send(res, 200, { posts: db.posts.filter(p => p.userId === uid) });
  if (pathname === '/api/posts' && req.method === 'POST') { const data = await body(req); db = readDb(); if (!data.sport || !data.date || !data.area) return send(res, 400, { error: '运动、日期和区域不能为空' }); const post = { id: id('post'), userId: uid, sport: String(data.sport), level: String(data.level || ''), date: String(data.date), time: String(data.time || ''), area: String(data.area), group: String(data.group || ''), fee: String(data.fee || ''), note: String(data.note || ''), status: '寻找中', createdAt: new Date().toISOString() }; db.posts.unshift(post); writeDb(db); return send(res, 201, { post }); }
  if (pathname === '/api/matches' && req.method === 'GET') {
    const matches = db.matches.filter(m => m.from === uid || m.to === uid).map(m => ({
      ...m,
      fromUser: safeUser(db, m.from),
      toUser: safeUser(db, m.to)
    }));
    return send(res, 200, { matches });
  }
  if (pathname === '/api/matches' && req.method === 'POST') { const data = await body(req); db = readDb(); if (!data.to || data.to === uid) return send(res, 400, { error: '匹配对象无效' }); if (!db.users.some(x => x.id === data.to)) return send(res, 404, { error: '用户不存在' }); const existing = db.matches.find(m => ((m.from === uid && m.to === data.to) || (m.from === data.to && m.to === uid)) && m.status !== 'declined'); if (existing) return send(res, 409, { error: existing.status === 'accepted' ? '你们已经匹配成功' : '已有待处理的匹配请求' }); const match = { id: id('match'), from: uid, to: data.to, status: 'pending', createdAt: new Date().toISOString() }; db.matches.push(match); writeDb(db); return send(res, 201, { match }); }
  if (pathname.startsWith('/api/matches/') && req.method === 'PATCH') { const data = await body(req); if (!['accepted', 'declined'].includes(data.status)) return send(res, 400, { error: '无效的匹配状态' }); db = readDb(); const match = db.matches.find(m => m.id === pathname.split('/').pop() && m.to === uid && m.status === 'pending'); if (!match) return send(res, 409, { error: '匹配请求不存在或已经处理' }); match.status = data.status; writeDb(db); return send(res, 200, { match }); }
  if (pathname === '/api/messages' && req.method === 'GET') {
    const matchId = new URL(req.url, `http://${req.headers.host}`).searchParams.get('match');
    const match = db.matches.find(m => m.id === matchId && m.status === 'accepted' && (m.from === uid || m.to === uid));
    if (!match) return send(res, 404, { error: '会话不存在或匹配尚未通过' });
    const messages = db.messages.filter(m => m.matchId === match.id).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    return send(res, 200, { messages });
  }
  if (pathname === '/api/messages' && req.method === 'POST') {
    const data = await body(req); db = readDb(); const text = String(data.text || '').trim();
    const match = db.matches.find(m => m.id === data.matchId && m.status === 'accepted' && (m.from === uid || m.to === uid));
    if (!match) return send(res, 404, { error: '会话不存在或匹配尚未通过' });
    if (!text) return send(res, 400, { error: '消息内容不能为空' });
    if (text.length > 500) return send(res, 400, { error: '消息不能超过 500 个字符' });
    const message = { id: id('msg'), matchId: match.id, from: uid, text, createdAt: new Date().toISOString() };
    db.messages.push(message); writeDb(db); return send(res, 201, { message });
  }
  if (pathname === '/api/activities' && req.method === 'GET') return send(res, 200, { activities: db.activities.filter(a => a.userId === uid) });
  return send(res, 404, { error: '接口不存在' });
}

const publicFiles = new Set(['/index.html', '/styles.css', '/app.js', '/leaflet.css', '/leaflet.js', '/images/marker-icon.png', '/images/marker-icon-2x.png', '/images/marker-shadow.png']);
const server = http.createServer(async (req, res) => { let pathname; try { pathname = decodeURIComponent((req.url || '/').split('?')[0]); } catch { res.writeHead(400); return res.end('Bad Request'); } if (pathname === '/health' && req.method === 'GET') return send(res, 200, { ok: true, service: 'sports-buddy' }); if (pathname.startsWith('/api/')) { try { await api(req, res, pathname); } catch (e) { send(res, 500, { error: e.message || '服务器错误' }); } return; } const requested = pathname === '/' ? '/index.html' : pathname; if (!publicFiles.has(requested)) { res.writeHead(404); return res.end('Not Found'); } const filePath = path.resolve(root, `.${requested}`); const relative = path.relative(root, filePath); if (relative.startsWith('..') || path.isAbsolute(relative)) { res.writeHead(403); return res.end('Forbidden'); } fs.readFile(filePath, (error, data) => { if (error) { res.writeHead(error.code === 'ENOENT' ? 404 : 500); return res.end(error.code === 'ENOENT' ? 'Not Found' : 'Server Error'); } res.writeHead(200, { 'Content-Type': mime[path.extname(filePath).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-cache' }); res.end(data); }); });
function startServer(listenPort = port, host = defaultHost) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, host, () => {
      server.removeListener('error', reject);
      const address = server.address();
      console.log(`知动乎网站已启动：http://${host}:${address.port}`);
      console.log(`用户数据保存在 ${dbFile}`);
      resolve(server);
    });
  });
}

if (require.main === module) startServer().catch(error => { console.error(error); process.exitCode = 1; });

module.exports = { server, startServer };
