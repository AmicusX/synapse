/**
 * Синапс · CORS-реле для OpenAI-совместимых API (Cloudflare Workers).
 * Браузер шлёт запрос сюда с заголовком x-target-url, воркер форвардит его
 * на целевой сервер и добавляет CORS-заголовки. Потоковые ответы (SSE) проходят насквозь.
 *
 * Переменные окружения (Settings → Variables):
 *   ALLOWED_TARGETS — список разрешённых хостов через запятую (по умолчанию ai.starimg.ru)
 *   RELAY_SECRET    — необязательный секрет; клиент шлёт его в x-relay-key
 */
const DEFAULT_ALLOWED = ["ai.starimg.ru"];
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, x-target-url, x-relay-key",
  "Access-Control-Max-Age": "86400",
};
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url);
    const target = req.headers.get("x-target-url") || url.searchParams.get("target");
    const json = (obj, status) => new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json" } });
    if (!target) return json({ error: "Передайте целевой URL в заголовке x-target-url или ?target=" }, 400);
    let t;
    try { t = new URL(target); } catch { return json({ error: "Некорректный целевой URL" }, 400); }
    if (t.protocol !== "https:") return json({ error: "Разрешён только https" }, 403);
    const allowed = (env.ALLOWED_TARGETS || DEFAULT_ALLOWED.join(",")).split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.length && !allowed.includes(t.hostname)) return json({ error: "Хост не в списке разрешённых: " + t.hostname }, 403);
    if (env.RELAY_SECRET && req.headers.get("x-relay-key") !== env.RELAY_SECRET) return json({ error: "Неверный секрет реле" }, 401);
    const headers = new Headers(req.headers);
    ["x-target-url", "x-relay-key", "host", "origin", "referer", "cf-connecting-ip", "cf-ray", "cf-visitor", "x-forwarded-for", "x-real-ip"].forEach(h => headers.delete(h));
    const resp = await fetch(t.toString(), {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
      redirect: "follow",
    });
    const out = new Headers(resp.headers);
    Object.entries(CORS).forEach(([k, v]) => out.set(k, v));
    return new Response(resp.body, { status: resp.status, headers: out });
  },
};