// Network-first service worker.
// The old cache-first strategy served index.html/app.js from cache forever (only a
// CACHE_NAME bump would update them), so a redeploy — including new CSP hashes for
// the inline scripts — never reached users. It also cached error responses and tried
// to fetch cross-origin fonts itself, which the page's CSP (connect-src 'self')
// blocks inside the worker. Now: same-origin GET static assets only, network first,
// cache used purely as an offline fallback; /api/ is never touched.
const CACHE_NAME = 'threatpulse-cache-v2';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/css/styles.css',
  '/js/app.js',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(
      names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Let the browser handle cross-origin (fonts) and API requests directly
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;

  event.respondWith(
    fetch(req).then((res) => {
      if (res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
      }
      return res;
    }).catch(() => caches.match(req).then((cached) => cached || Response.error()))
  );
});
