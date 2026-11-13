-- Agent-state schema for the `agent_state` database on the cluster H1 provisions.
-- docs/hr/modules.md § Database roles names `agent_checkpoint` as the owner
-- of the god agent's LangGraph checkpoint tables, with no access to the HR
-- database. This file creates the role in `agent_state` only; it is applied
-- separately from schema.sql, which targets the `hr` database.
--
-- H1 does NOT create the checkpoint tables themselves. The god agent runs
-- `PostgresSaver.setup()` at Layer 2 and that creates
-- `checkpoints`/`checkpoint_blobs`/`checkpoint_writes`/`checkpoint_migrations`.
-- Our only job is to make sure the role exists with the privileges that
-- call needs. Idempotent so a redeploy does not fail.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_checkpoint') THEN
        EXECUTE 'CREATE ROLE agent_checkpoint LOGIN';
    END IF;
END
$$;

-- Required for RDS IAM authentication (docs/hr/modules.md). Safe to repeat.
GRANT rds_iam TO agent_checkpoint;

-- `PostgresSaver.setup()` creates its four tables and the matching indexes
-- in the public schema. CREATE on the schema is required for that; USAGE
-- is required to resolve objects on every subsequent connection.
GRANT CONNECT ON DATABASE CURRENT_DATABASE() TO agent_checkpoint;
GRANT USAGE, CREATE ON SCHEMA public TO agent_checkpoint;

-- agent_checkpoint OWNS every object it creates. Granting default privileges
-- on future objects keeps the right-to-use grant stable across setup() and
-- LangGraph's own index creation, which may create sequences and indexes we
-- did not predict here.
ALTER DEFAULT PRIVILEGES FOR ROLE agent_checkpoint IN SCHEMA public
    GRANT ALL ON TABLES TO agent_checkpoint;
ALTER DEFAULT PRIVILEGES FOR ROLE agent_checkpoint IN SCHEMA public
    GRANT ALL ON SEQUENCES TO agent_checkpoint;
