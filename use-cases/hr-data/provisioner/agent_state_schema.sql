-- Agent-state schema for the `agent_state` database on the cluster H1 provisions.
-- docs/hr/modules.md § Database roles names `agent_checkpoint` as the owner
-- of the god agent's LangGraph checkpoint tables, with no access to the HR
-- database. This file creates the role in `agent_state` only; it is applied
-- separately from schema.sql, which targets the `hr` database.
--
-- H1 does NOT create the checkpoint tables themselves. The god agent runs
-- `AsyncPostgresSaver.setup()` at Layer 2 and that creates
-- `checkpoints`/`checkpoint_blobs`/`checkpoint_writes`/`checkpoint_migrations`.
-- Idempotent so a redeploy does not fail.

DO $$
DECLARE
    db text := current_database();
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_checkpoint') THEN
        EXECUTE 'CREATE ROLE agent_checkpoint LOGIN';
    END IF;
    EXECUTE 'GRANT rds_iam TO agent_checkpoint';
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO agent_checkpoint', db);
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO agent_checkpoint;

ALTER DEFAULT PRIVILEGES FOR ROLE agent_checkpoint IN SCHEMA public
    GRANT ALL ON TABLES TO agent_checkpoint;
ALTER DEFAULT PRIVILEGES FOR ROLE agent_checkpoint IN SCHEMA public
    GRANT ALL ON SEQUENCES TO agent_checkpoint;
