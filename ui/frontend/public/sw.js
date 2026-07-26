// recon-ui service worker — minimal, makes the app installable (Brave/Chromium).
// Network-first for navigations (always fresh app shell when online); never touches
// /api or websockets; caches hashed static assets for offline shell.
const CACHE = "recon-ui-v3";

self.addEventListener("install", (e) => {
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET") return;
  if (url.pathname.startsWith("/api/")) return; // never cache API or WS

  // navigations: network-first, cache fallback (offline shell)
  if (e.request.mode === "navigate") {
    e.respondWith(
      fetch(e.request)
        .then((r) => { const c = r.clone(); caches.open(CACHE).then((ca) => ca.put("/", c)); return r; })
        .catch(() => caches.match("/"))
    );
    return;
  }

  // hashed static assets: cache-first, update in background
  if (url.pathname.startsWith("/assets/") || url.pathname.startsWith("/icons/")) {
    e.respondWith(
      caches.match(e.request).then((hit) =>
        hit || fetch(e.request).then((r) => { const c = r.clone(); caches.open(CACHE).then((ca) => ca.put(e.request, c)); return r; })
      )
    );
  }
});
