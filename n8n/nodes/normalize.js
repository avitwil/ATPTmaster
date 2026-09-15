// ATPTmaster :: Phase 1 Normalizer  (N8N Code node, "Run Once for All Items")
// IN : item(s) with json.stdout = JSONL from recon_runner.sh
// OUT: one deduped item per canonical asset, keys == public.assets columns.
const lines = [];
for (const item of $input.all()) {
  const out = item.json.stdout ?? item.json.data ?? '';
  for (const l of String(out).split('\n')) {
    const s = l.trim();
    if (!s) continue;
    try { lines.push(JSON.parse(s)); } catch (_) { /* skip log/non-JSON lines */ }
  }
}
const host_of = (v) => v ? String(v).replace(/^\w+:\/\//, '').split('/')[0].split(':')[0] : null;
const norm = (r) => {
  const base = {
    engagement_id: r._engagement_id ?? null, source_tool: r._tool ?? 'unknown', raw: r,
    asset_type: null, value: null, host: null, ip: null, port: null, protocol: null,
    service: null, product: null, version: null, http_status: null, http_title: null,
    tech: null, url: null,
  };
  switch (r._tool) {
    case 'subfinder':
      return { ...base, asset_type: 'subdomain', host: r.host ?? r.input ?? null,
               value: r.host ?? r.input ?? null };
    case 'naabu':
      return { ...base, asset_type: 'service', host: r.host ?? r.ip ?? null, ip: r.ip ?? null,
               port: r.port ?? null, protocol: 'tcp', value: `${r.host ?? r.ip}:${r.port}` };
    case 'nmap':
      return { ...base, asset_type: 'service', host: r.host ?? r.ip ?? null, ip: r.ip ?? null,
               port: r.port ?? null, protocol: r.protocol ?? 'tcp', service: r.service ?? null,
               product: r.product ?? null, version: r.version ?? null,
               value: `${r.host ?? r.ip}:${r.port}/${r.service ?? ''}` };
    case 'httpx':
      return { ...base, asset_type: 'web_endpoint', host: r.host ?? host_of(r.input) ?? null,
               ip: (Array.isArray(r.a) ? r.a[0] : null), port: r.port ? Number(r.port) : null,
               protocol: 'tcp', service: r.scheme ?? null,
               http_status: r.status_code ?? null, http_title: r.title ?? null,
               tech: Array.isArray(r.tech) ? r.tech : (r.technologies ?? null),
               url: r.url ?? null, value: r.url ?? null };
    case 'ffuf':
      return { ...base, asset_type: 'web_path', host: host_of(r.base), url: r.url ?? null,
               http_status: r.status ?? null, value: r.url ?? null };
    default:
      return { ...base, asset_type: 'unknown', value: JSON.stringify(r).slice(0, 200) };
  }
};
const seen = new Set(); const items = [];
for (const r of lines) {
  const a = norm(r);
  if (!a.value) continue;
  const key = `${a.asset_type}|${a.value}`;
  if (seen.has(key)) continue;
  seen.add(key);
  items.push({ json: { ...a,
    tech: a.tech ? JSON.stringify(a.tech) : null,
    raw:  a.raw  ? JSON.stringify(a.raw)  : null } });
}
return items;
