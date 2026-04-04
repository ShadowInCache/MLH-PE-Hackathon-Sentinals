import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost';

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '1m', target: 50 },
    { duration: '1m', target: 200 },
    { duration: '2m', target: 200 },
    { duration: '2m', target: 500 },
    { duration: '3m', target: 500 },
    { duration: '30s', target: 0 }
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'],
    http_req_failed: ['rate<0.05']
  }
};

const createdCodes = [];
const createdIds = [];

function randomInt(max) {
  return Math.floor(Math.random() * max);
}

function randomSlug(length) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += alphabet[randomInt(alphabet.length)];
  }
  return out;
}

function randomUrl() {
  return `https://traffic-source.example/${randomSlug(8)}/${Date.now()}-${randomInt(10000)}`;
}

function doShorten() {
  const payload = JSON.stringify({
    original_url: randomUrl(),
    title: `load-${randomSlug(6)}`
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    responseCallback: http.expectedStatuses(200, 201)
  };

  const res = http.post(`${BASE_URL}/shorten`, payload, params);

  check(res, {
    'shorten returns 200/201': (r) => r.status === 200 || r.status === 201
  });

  let body = {};
  try {
    body = res.json();
  } catch (err) {
    body = {};
  }

  if (body && body.short_code) {
    createdCodes.push(body.short_code);
  }
  if (body && body.id !== undefined && body.id !== null) {
    createdIds.push(String(body.id));
  }
}

function doRedirect() {
  if (createdCodes.length === 0) {
    doShorten();
    return;
  }

  const code = createdCodes[randomInt(createdCodes.length)];
  const params = {
    redirects: 0,
    responseCallback: http.expectedStatuses(301, 302, 307, 308)
  };

  const res = http.get(`${BASE_URL}/${code}`, params);

  check(res, {
    'redirect returns 3xx': (r) => r.status >= 300 && r.status < 400
  });
}

function doDelete() {
  if (createdIds.length === 0) {
    doShorten();
    return;
  }

  const id = createdIds[randomInt(createdIds.length)];
  const params = {
    responseCallback: http.expectedStatuses(200, 202, 204, 404)
  };

  const res = http.del(`${BASE_URL}/urls/${id}`, null, params);

  check(res, {
    'delete returns expected status': (r) => [200, 202, 204, 404].includes(r.status)
  });
}

function doHealth() {
  const params = {
    responseCallback: http.expectedStatuses(200, 503)
  };

  const res = http.get(`${BASE_URL}/health`, params);

  check(res, {
    'health returns 200 or 503': (r) => r.status === 200 || r.status === 503
  });
}

export default function () {
  const trafficRoll = Math.random() * 100;

  if (trafficRoll < 58) {
    doShorten();
  } else if (trafficRoll < 93) {
    doRedirect();
  } else if (trafficRoll < 99) {
    doDelete();
  } else {
    doHealth();
  }

  sleep(0.1 + Math.random() * 0.4);
}
