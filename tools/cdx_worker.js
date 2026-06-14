// cdx_worker.js — Cloudflare Worker: a LOCKED passthrough to the Wayback CDX API.
//
// WHY: web.archive.org's wayback/CDX subnet (207.241.237.0/24) blocks our Mullvad
// datacenter egress, killing gau/waybackurls param-URL discovery. This Worker fetches
// CDX from Cloudflare's egress (not on IA's VPN blocklist) and returns the URL list.
// The recon pipeline calls THIS worker over Mullvad — target traffic never leaves the
// tunnel; only public archive OSINT egresses via Cloudflare; our real IP is never exposed.
//
// SAFETY: it is NOT a general proxy — it only ever fetches web.archive.org CDX for a
// validated `domain`, gated by a shared secret (AUTH_SECRET). A leaked secret only lets
// someone query public archive data, never anything else.
//
// Deploy: Workers & Pages -> Create -> Worker -> paste this -> Deploy.
// Then Settings -> Variables and Secrets -> add SECRET `AUTH_SECRET` (a long random string).

export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    const key = request.headers.get("x-auth") || u.searchParams.get("k") || "";
    if (!env.AUTH_SECRET || key !== env.AUTH_SECRET) {
      return new Response("forbidden\n", { status: 403 });
    }
    const domain = (u.searchParams.get("domain") || "").trim().toLowerCase();
    if (!/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(domain)) {
      return new Response("bad domain\n", { status: 400 });
    }
    const limit = Math.min(parseInt(u.searchParams.get("limit") || "5000", 10) || 5000, 50000);
    // subs=1 -> include subdomains (matchType=domain); else host-scoped prefix
    const subs = u.searchParams.get("subs") === "1";
    const cdx = "https://web.archive.org/cdx/search/cdx?" + new URLSearchParams({
      url: subs ? domain : domain + "/*",
      ...(subs ? { matchType: "domain" } : {}),
      output: "text",
      fl: "original",
      collapse: "urlkey",
      limit: String(limit),
    }).toString();
    try {
      const r = await fetch(cdx, {
        headers: { "User-Agent": "Mozilla/5.0 (cdx-proxy)" },
        cf: { cacheTtl: 600, cacheEverything: true },
      });
      if (!r.ok) return new Response("upstream " + r.status + "\n", { status: 502 });
      return new Response(r.body, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    } catch (e) {
      return new Response("upstream error\n", { status: 502 });
    }
  },
};
