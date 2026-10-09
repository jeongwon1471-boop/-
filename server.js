const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

const password = process.env.ADMIN_PASSWORD;
const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!password || !url || !key) {
  console.error('Render 환경변수를 확인하세요.');
  process.exit(1);
}

const supabase = createClient(url, key, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

const sessions = new Map();
const attempts = new Map();

const today = () =>
  new Date(Date.now() + 9 * 3600000)
    .toISOString()
    .slice(0, 10);

const validId = n =>
  Number.isSafeInteger(n) && n > 0;

const validMonth = s =>
  /^\d{4}-(0[1-9]|1[0-2])$/.test(s);

function fail(res, e) {
  console.error(e);
  return res.status(400).json({
    error: e.message || '처리 중 오류가 발생했습니다.'
  });
}

function admin(req, res, next) {
  const token = (req.headers.authorization || '')
    .replace(/^Bearer /, '');

  const expires = sessions.get(token);

  if (!expires || expires < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({
      error: '관리자 로그인이 필요합니다.'
    });
  }

  next();
}

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/people', async (req, res) => {
  const { data, error } = await supabase
    .from('people')
    .select('id,name')
    .eq('active', true)
    .order('name');

  if (error) return fail(res, error);
  res.json(data);
});

app.get('/api/restaurants', async (req, res) => {
  const { data, error } = await supabase
    .from('restaurants')
    .select('id,name')
    .eq('active', true)
    .order('name');

  if (error) return fail(res, error);
  res.json(data);
});

app.get('/api/usage', async (req, res) => {
  const id = Number(req.query.person);
  const month = String(req.query.month || today().slice(0, 7));

  if (!validId(id) || !validMonth(month)) {
    return res.status(400).json({
      error: '조회 조건 오류'
    });
  }

  const { data, error } = await supabase
    .from('restaurant_usage')
    .select('restaurant_id,count')
    .eq('person_id', id)
    .gte('day', month + '-01')
    .lte('day', month + '-31');

  if (error) return fail(res, error);

  const totals = {};

  for (const row of data) {
    totals[row.restaurant_id] =
      (totals[row.restaurant_id] || 0) + row.count;
  }

  res.json(
    Object.entries(totals).map(([restaurant_id, count]) => ({
      restaurant_id: Number(restaurant_id),
      count
    }))
  );
});

app.post('/api/click', async (req, res) => {
  const p = Number(req.body?.person);
  const r = Number(req.body?.restaurant);
  const delta = req.body?.delta;

  if (!validId(p) || !validId(r) || ![-1, 1].includes(delta)) {
    return res.status(400).json({
      error: '입력값 오류'
    });
  }

  const { data, error } = await supabase.rpc(
    'change_ticket_count',
    {
      p_person_id: p,
      p_restaurant_id: r,
      p_day: today(),
      p_delta: delta
    }
  );

  if (error) return fail(res, error);

  res.json({ todayCount: data });
});

app.post('/api/admin/login', (req, res) => {
  const ip = req.ip;
  const a = attempts.get(ip) || {
    count: 0,
    until: 0
  };

  if (a.until > Date.now()) {
    return res.status(429).json({
      error: '15분 후 다시 시도하세요.'
    });
  }

  const entered = crypto
    .createHash('sha256')
    .update(String(req.body?.password || ''))
    .digest();

  const expected = crypto
    .createHash('sha256')
    .update(password)
    .digest();

  if (!crypto.timingSafeEqual(entered, expected)) {
    a.count++;

    if (a.count >= 5) {
      a.count = 0;
      a.until = Date.now() + 900000;
    }

    attempts.set(ip, a);

    return res.status(401).json({
      error: '비밀번호가 틀렸습니다.'
    });
  }

  attempts.delete(ip);

  const token = crypto.randomBytes(32).toString('hex');

  sessions.set(token, Date.now() + 43200000);

  res.json({ token });
});

app.post('/api/admin/logout', admin, (req, res) => {
  const token = (req.headers.authorization || '')
    .replace(/^Bearer /, '');

  sessions.delete(token);
  res.json({ ok: true });
});

for (const route of ['people', 'restaurants']) {

  app.get('/api/admin/' + route, admin, async (req, res) => {
    const { data, error } = await supabase
      .from(route)
      .select('id,name,active')
      .order('name');

    if (error) return fail(res, error);
    res.json(data);
  });

  app.post('/api/admin/' + route, admin, async (req, res) => {
    const name = String(req.body?.name || '').trim();

    if (!name || name.length > 80) {
      return res.status(400).json({
        error: '이름을 1~80자로 입력하세요.'
      });
    }

    const { data: old, error: findError } = await supabase
      .from(route)
      .select('id')
      .eq('name', name)
      .maybeSingle();

    if (findError) return fail(res, findError);

    let result;

    if (old) {
      result = await supabase
        .from(route)
        .update({ active: true })
        .eq('id', old.id);
    } else {
      result = await supabase
        .from(route)
        .insert({ name });
    }

    if (result.error) return fail(res, result.error);

    res.json({ ok: true });
  });

  app.patch('/api/admin/' + route + '/:id',
    admin,
    async (req, res) => {

      const id = Number(req.params.id);

      if (!validId(id) ||
          typeof req.body?.active !== 'boolean') {
        return res.status(400).json({
          error: '입력 오류'
        });
      }

      const { error } = await supabase
        .from(route)
        .update({ active: req.body.active })
        .eq('id', id);

      if (error) return fail(res, error);

      res.json({ ok: true });
    }
  );
}

app.get('/api/admin/report', admin, async (req, res) => {
  const month = String(req.query.month || today().slice(0, 7));

  if (!validMonth(month)) {
    return res.status(400).json({
      error: '월 형식 오류'
    });
  }

  const { data, error } = await supabase
    .from('restaurant_usage')
    .select(`
      day,
      count,
      people(name),
      restaurants(name)
    `)
    .gte('day', month + '-01')
    .lte('day', month + '-31')
    .gt('count', 0)
    .order('day');

  if (error) return fail(res, error);

  res.json(data.map(row => ({
    person: row.people?.name || '',
    restaurant: row.restaurants?.name || '',
    day: row.day,
    count: row.count
  })));
});

app.listen(
  process.env.PORT || 3000,
  '0.0.0.0',
  () => console.log('식권 서버 실행 중 - Supabase 연결')
);
