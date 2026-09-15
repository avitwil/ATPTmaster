-- ATPTmaster :: State Tree — Phase 1 (Recon) core tables
-- Recon populates `assets`. Later phases populate `findings`.
-- This file locks the canonical contract every downstream node relies on.

CREATE TABLE IF NOT EXISTS engagements (
  id            text PRIMARY KEY,          -- e.g. "ACME-2026-Q3"
  name          text,
  scope         jsonb,                     -- snapshot of scope.json used
  status        text DEFAULT 'active',
  created_at    timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
  id            bigserial PRIMARY KEY,
  engagement_id text NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  asset_type    text NOT NULL,             -- subdomain | service | web_endpoint | web_path
  value         text NOT NULL,             -- canonical identity of the asset
  host          text,
  ip            text,
  port          integer,
  protocol      text,
  service       text,
  product       text,
  version       text,
  http_status   integer,
  http_title    text,
  tech          jsonb,
  url           text,
  source_tool   text,                      -- subfinder|naabu|nmap|httpx|ffuf
  raw           jsonb,                      -- full native tool record
  first_seen    timestamptz DEFAULT now(),
  last_seen     timestamptz DEFAULT now(),
  UNIQUE (engagement_id, asset_type, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_eng  ON assets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);

-- Defined now so the contract is stable before Phase 3/4 write to it.
CREATE TABLE IF NOT EXISTS findings (
  id            bigserial PRIMARY KEY,
  engagement_id text NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  asset_id      bigint REFERENCES assets(id) ON DELETE SET NULL,
  title         text NOT NULL,
  domain        text,                      -- web|sqli|infra|api|mobile|llm|cloud|wireless
  severity      text,                      -- info|low|medium|high|critical
  cvss          numeric(3,1),
  owasp         text,
  status        text DEFAULT 'candidate',  -- candidate|validated|false_positive
  evidence      jsonb,
  source_tool   text,
  created_at    timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_eng ON findings(engagement_id);
