-- 001_ledger_events: hash-chained event ledgers with per-tenant row level security (ES-006).
-- Run by the schema owner (needs CREATEROLE the first time). The application never connects as the owner.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easysign_app') THEN
    CREATE ROLE easysign_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easysign_auditor') THEN
    CREATE ROLE easysign_auditor NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

CREATE TABLE public.ledger_events (
  ledger    text        NOT NULL CHECK (ledger ~ '^[a-z][a-z0-9_]{0,62}$'),
  seq       bigint      NOT NULL CHECK (seq > 0),
  tenant_id text        NOT NULL CHECK (tenant_id <> ''),
  type      text        NOT NULL CHECK (type <> ''),
  at        timestamptz NOT NULL,
  payload   jsonb       NOT NULL,
  prev_hash text        NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash      text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (ledger, seq)
);
CREATE INDEX ledger_events_tenant_idx ON public.ledger_events (ledger, tenant_id, seq);

-- One row per ledger: the last sequence number and hash. It carries no tenant data (a counter and a SHA-256),
-- so it has no row level security; the application can read it but only the trigger below can change it.
CREATE TABLE public.ledger_heads (
  ledger    text   PRIMARY KEY,
  last_seq  bigint NOT NULL CHECK (last_seq >= 0),
  last_hash text   NOT NULL CHECK (last_hash ~ '^[0-9a-f]{64}$')
);

-- The database itself enforces the chain: an event is accepted only if it extends the current head.
-- SQLSTATE 40001 tells the application to re-read the head and retry.
CREATE FUNCTION public.ledger_events_extend_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  INSERT INTO public.ledger_heads (ledger, last_seq, last_hash)
  VALUES (NEW.ledger, 0, repeat('0', 64))
  ON CONFLICT (ledger) DO NOTHING;

  UPDATE public.ledger_heads
     SET last_seq = NEW.seq, last_hash = NEW.hash
   WHERE ledger = NEW.ledger AND last_seq = NEW.seq - 1 AND last_hash = NEW.prev_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ledger "%": event % does not extend the current head', NEW.ledger, NEW.seq USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION public.ledger_events_extend_chain() FROM PUBLIC;

CREATE TRIGGER ledger_events_extend_chain BEFORE INSERT ON public.ledger_events
  FOR EACH ROW EXECUTE FUNCTION public.ledger_events_extend_chain();

-- Append-only for everyone, the owner included.
CREATE FUNCTION public.ledger_events_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'ledger_events is append-only (% is not allowed)', TG_OP USING ERRCODE = '42501';
END
$$;

CREATE TRIGGER ledger_events_no_update_delete BEFORE UPDATE OR DELETE ON public.ledger_events
  FOR EACH ROW EXECUTE FUNCTION public.ledger_events_append_only();
CREATE TRIGGER ledger_events_no_truncate BEFORE TRUNCATE ON public.ledger_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.ledger_events_append_only();

-- Tenant isolation. FORCE makes the policies apply to the table owner too.
-- app.tenant_id is set per transaction (SET LOCAL / set_config(..., true)); unset or empty matches no row.
ALTER TABLE public.ledger_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ledger_events FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_read ON public.ledger_events FOR SELECT TO easysign_app
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_append ON public.ledger_events FOR INSERT TO easysign_app
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- Read-only role for whole-chain verification and evidence export; never used by the API process.
CREATE POLICY auditor_read ON public.ledger_events FOR SELECT TO easysign_auditor USING (true);

REVOKE ALL ON public.ledger_events, public.ledger_heads FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO easysign_app, easysign_auditor;
GRANT SELECT, INSERT ON public.ledger_events TO easysign_app;
GRANT SELECT ON public.ledger_events TO easysign_auditor;
GRANT SELECT ON public.ledger_heads TO easysign_app, easysign_auditor;
