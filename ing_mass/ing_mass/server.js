const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// простая загрузка .env
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n').forEach(l => {
    const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  });
} catch (e) {}

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

const D = f => path.join(__dirname, 'data', f);
const read = f => JSON.parse(fs.readFileSync(D(f), 'utf8'));
const write = (f, d) => fs.writeFileSync(D(f), JSON.stringify(d, null, 2));

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.token, JWT_SECRET);
    const user = read('users.json').find(u => u.id === p.id);
    if (!user) throw 0;
    req.user = user; next();
  } catch (e) { res.status(401).json({ error: 'Войдите в аккаунт' }); }
}
const pub = u => ({ id: u.id, name: u.name, email: u.email, phone: u.phone });
function setToken(res, user) {
  const t = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', t, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 864e5 });
}

app.get('/api/products', (req, res) => res.json(read('products.json')));
app.get('/api/post-offices', (req, res) => res.json(read('post_offices.json')));

app.post('/api/register', (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Заполните имя, email и пароль (от 6 символов)' });
  const users = read('users.json');
  const mail = String(email).trim().toLowerCase();
  if (users.some(u => u.email === mail)) return res.status(400).json({ error: 'Такой email уже зарегистрирован' });
  const user = { id: crypto.randomUUID(), name: String(name).slice(0, 60), email: mail,
    phone: String(phone || '').slice(0, 20), hash: bcrypt.hashSync(password, 10) };
  users.push(user); write('users.json', users);
  setToken(res, user); res.json(pub(user));
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = read('users.json').find(u => u.email === String(email || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ''), user.hash))
    return res.status(400).json({ error: 'Неверный email или пароль' });
  setToken(res, user); res.json(pub(user));
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

app.delete('/api/me', auth, (req, res) => {
  if (!bcrypt.compareSync(String((req.body || {}).password || ''), req.user.hash))
    return res.status(400).json({ error: 'Неверный пароль' });
  write('users.json', read('users.json').filter(u => u.id !== req.user.id));
  res.clearCookie('token'); res.json({ ok: true });
});

app.get('/api/orders', auth, (req, res) =>
  res.json(read('orders.json').filter(o => o.userId === req.user.id).reverse()));

async function sendTelegram(text) {
  if (!BOT_TOKEN || !ADMIN_CHAT_ID) throw new Error('Telegram не настроен (BOT_TOKEN / ADMIN_CHAT_ID)');
  const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: ADMIN_CHAT_ID, text })
  });
  const j = await r.json();
  if (!j.ok) throw new Error('Telegram: ' + j.description);
}

app.post('/api/checkout', auth, async (req, res) => {
  try {
    const { items, officeId } = req.body || {};
    const products = read('products.json');
    const office = read('post_offices.json').find(o => o.id === officeId);
    if (!office) return res.status(400).json({ error: 'Выберите отделение почты' });
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Корзина пуста' });
    let total = 0; const lines = [];
    for (const it of items) {
      const p = products.find(x => x.id === it.id);
      const qty = Math.min(Math.max(parseInt(it.qty) || 0, 1), 50);
      if (!p) continue;
      total += p.price * qty;
      lines.push({ id: p.id, name: p.name, price: p.price, qty });
    }
    if (!lines.length) return res.status(400).json({ error: 'Корзина пуста' });
    const order = { id: Date.now().toString().slice(-8), userId: req.user.id, date: new Date().toISOString(),
      items: lines, total, office };
    const text = `🛒 Новый заказ №${order.id} (Ing_mass)\n\n` +
      `Покупатель: ${req.user.name}\nТелефон: ${req.user.phone || '—'}\nEmail: ${req.user.email}\n\n` +
      `Товары:\n` + lines.map(l => `• ${l.name} × ${l.qty} = ${l.price * l.qty} ₽`).join('\n') +
      `\n\nОплачено: ${total} ₽\n\nОтправить в: ${office.name}\n${office.address}`;
    await sendTelegram(text);
    const orders = read('orders.json'); orders.push(order); write('orders.json', orders);
    res.json(order);
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log('Ing_mass: http://localhost:' + PORT));
