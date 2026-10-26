// Performance: 10 virtual users for 30s against pre-production, logged in,
// on the paths a user actually hits. verdict.py k6 decides: p95 within the
// SLO, <1% failed requests, >=99% checks passed.
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL;
const API = `${BASE}/api/method/frappe_gates_demo.api.`;

export const options = {
  vus: 10,
  duration: '30s',
  // Each VU is one user who logs in once. k6's default clears the jar every
  // iteration, which would re-login (a deliberately slow password hash)
  // ~30 times a second and measure the hasher, not the app.
  noCookiesReset: true,
};

function loggedIn() {
  return (http.cookieJar().cookiesForURL(BASE).sid || []).length > 0;
}

function login() {
  const page = http.get(`${BASE}/login`);
  if (!check(page, { 'login page 200': (res) => res.status === 200 })) {
    return false;
  }
  const r = http.post(`${BASE}/api/method/login`, {
    usr: __ENV.USER_A,
    pwd: __ENV.PASSWORD_A,
  });
  return check(r, { 'login 200': (res) => res.status === 200 });
}

export default function () {
  if (!loggedIn() && !login()) {
    sleep(1); // counted as failed checks; don't hammer a broken login
    return;
  }

  check(http.get(`${API}health`), { 'health ok': (r) => r.status === 200 });
  check(http.get(`${BASE}/notes`), { 'page 200': (r) => r.status === 200 });
  check(http.get(`${API}notes_list?limit=20`), { 'list 200': (r) => r.status === 200 });

  // Writes at a fifth of the read rate: enough to exercise the insert path
  // (validation, permissions, the naming series) without filling the site.
  if (__ITER % 5 === 0) {
    const created = http.post(
      `${API}note_create`,
      JSON.stringify({ title: `k6 ${__VU}-${__ITER}`, severity: 'Low' }),
      { headers: { 'Content-Type': 'application/json' } },
    );
    check(created, { 'create 200': (r) => r.status === 200 });
    if (created.status === 200) {
      const name = created.json('message.name');
      check(
        http.post(`${API}note_close`, JSON.stringify({ name }), {
          headers: { 'Content-Type': 'application/json' },
        }),
        { 'close 200': (r) => r.status === 200 },
      );
    }
  }
  sleep(0.2);
}

export function handleSummary(data) {
  return { [__ENV.SUMMARY_OUT || 'k6-summary.json']: JSON.stringify(data) };
}
