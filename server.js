const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ================= НАСТРОЙКИ =================
const BOT_TOKEN = 'ВСТАВЬТЕ_ТОКЕН_БОТА';      // от @BotFather
const ADMIN_CHAT_ID = 'ВСТАВЬТЕ_ВАШ_CHAT_ID';  // от @userinfobot
const JWT_SECRET = 'замените-на-любую-длинную-случайную-строку';
const PORT = 3000;

// Товары (цены поставьте свои)
const PRODUCTS = [
  { id: 'whey', name: 'Сывороточный протеин PrimeKraft, 900 г (молочный шоколад)', price: 2500, image: 'img/whey.jpg',
    description: 'Изолят сывороточного белка с витаминно-минеральным комплексом. 23 г белка и 6,7 г BCAA в порции (30 г), 30 порций в банке. Подходит для набора мышечной массы и похудения. Вкус: молочный шоколад.' },
  { id: 'bcaa', name: 'BCAA 2:1:1 PrimeKraft, 150 г (ананас)', price: 1500, image: 'img/bcaa.jpg',
    description: 'Аминокислоты в соотношении 2:1:1. 3900 мг аминокислот в порции (5 г), 30 порций. Помогает восстановлению после нагрузок, поддерживает белковый обмен, силу и выносливость. Вкус: ананас.' },
  { id: 'creatine', name: 'Креатин моногидрат PrimeKraft, 200 г', price: 1300, image: 'img/creatine.jpg',
    description: 'Микронизированный креатин моногидрат, 5000 мг в порции, 40 порций. Ускоряет рост мышечной массы, увеличивает энергию во время тренировки, повышает выносливость. Вкус: чистый.' },
  { id: 'gainer', name: 'Гейнер Ironman Turbo Mass Gainer, 1,4 кг (банан)', price: 2200, image: 'img/gainer.jpg',
    description: 'Гейнер для быстрого набора массы. Только молочный белок, без сои, низкое содержание жира, 10 витаминов. Вкус: банан. Вес 1,4 кг.' },
  { id: 'zma', name: 'ZMA комплекс + B6 Mishido, 60 капсул', price: 1100, image: 'img/zma.jpg',
    description: 'Усиленная формула: цинк 25 мг, магний 600 мг, витамин B6 6 мг, аспарагиновая кислота 19 мг. 60 капсул, по 1 капсуле в день. Поддержка роста мышц, выносливости и мужской силы. БАД, не является лекарством.' }
];

// Отделения Почты России в Ингушетии.
// Индексы проверьте на pochta.ru, впишите улицы и добавьте остальные отделения по образцу.
const OFFICES = [
  { id: '386001', name: 'Почта России 386001', address: 'Республика Ингушетия, г. Магас, ул. ...' },
  { id: '386100', name: 'Почта России 386100', address: 'Республика Ингушетия, г. Назрань, ул. ...' },
  { id: '386231', name: 'Почта России 386231', address: 'Республика Ингушетия, г. Карабулак, ул. ...' },
  { id: '386300', name: 'Почта России 386300', address: 'Республика Ингушетия, г. Малгобек, ул. ...' },
  { id: '386210', name: 'Почта России 386210', address: 'Республика Ингушетия, г. Сунжа, ул. ...' }
];
// =============================================

const DB_FILE = path.join(__dirname, 'db.json');
const load = () => { try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { return { users: [], orders: [] }; } };
const save = d => fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2));

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use('/img', express.static(path.join(__dirname, 'img')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.token, JWT_SECRET);
    const user = load().users.find(u => u.id === p.id);
    if (!user) throw 0;
    req.user = user; next();
  } catch (e) { res.status(401).json({ error: 'Войдите в аккаунт' }); }
}
const pub = u => ({ id: u.id, name: u.name, email: u.email, phone: u.phone });
function setToken(res, user) {
  const t = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', t, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 864e5 });
}

app.get('/api/products', (req, res) => res.json(PRODUCTS));
app.get('/api/post-offices', (req, res) => res.json(OFFICES));

app.post('/api/register', (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Заполните имя, email и пароль (от 6 символов)' });
  const db = load();
  const mail = String(email).trim().toLowerCase();
  if (db.users.some(u => u.email === mail)) return res.status(400).json({ error: 'Такой email уже зарегистрирован' });
  const user = { id: crypto.randomUUID(), name: String(name).slice(0, 60), email: mail,
    phone: String(phone || '').slice(0, 20), hash: bcrypt.hashSync(password, 10) };
  db.users.push(user); save(db);
  setToken(res, user); res.json(pub(user));
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = load().users.find(u => u.email === String(email || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ''), user.hash))
    return res.status(400).json({ error: 'Неверный email или пароль' });
  setToken(res, user); res.json(pub(user));
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

app.delete('/api/me', auth, (req, res) => {
  if (!bcrypt.compareSync(String((req.body || {}).password || ''), req.user.hash))
    return res.status(400).json({ error: 'Неверный пароль' });
  const db = load();
  db.users = db.users.filter(u => u.id !== req.user.id);
  save(db);
  res.clearCookie('token'); res.json({ ok: true });
});

app.get('/api/orders', auth, (req, res) =>
  res.json(load().orders.filter(o => o.userId === req.user.id).reverse()));

async function sendTelegram(text) {
  const r = await fetch('https://api.telegram.org/bot' + BOT_TOKEN + '/sendMessage', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: ADMIN_CHAT_ID, text })
  });
  const j = await r.json();
  if (!j.ok) throw new Error('Telegram: ' + j.description);
}

app.post('/api/checkout', auth, async (req, res) => {
  try {
    const { items, officeId } = req.body || {};
    const office = OFFICES.find(o => o.id === officeId);
    if (!office) return res.status(400).json({ error: 'Выберите отделение почты' });
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Корзина пуста' });
    let total = 0; const lines = [];
    for (const it of items) {
      const p = PRODUCTS.find(x => x.id === it.id);
      const qty = Math.min(Math.max(parseInt(it.qty) || 0, 1), 50);
      if (!p) continue;
      total += p.price * qty;
      lines.push({ id: p.id, name: p.name, price: p.price, qty });
    }
    if (!lines.length) return res.status(400).json({ error: 'Корзина пуста' });
    const order = { id: Date.now().toString().slice(-8), userId: req.user.id, date: new Date().toISOString(),
      items: lines, total, office };
    const text = '🛒 Новый заказ №' + order.id + ' (Ing_mass)\n\n' +
      'Покупатель: ' + req.user.name + '\nТелефон: ' + (req.user.phone || '—') + '\nEmail: ' + req.user.email + '\n\n' +
      'Товары:\n' + lines.map(l => '• ' + l.name + ' × ' + l.qty + ' = ' + (l.price * l.qty) + ' ₽').join('\n') +
      '\n\nОплачено: ' + total + ' ₽\n\nОтправить в: ' + office.name + '\n' + office.address;
    await sendTelegram(text);
    const db = load(); db.orders.push(order); save(db);
    res.json(order);
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log('Ing_mass: http://localhost:' + PORT));