-- HR schema for the `hr` database on the cluster H1 provisions.
-- Spec: docs/hr/schema.md. Applied on every deploy by provisioner/handler.py.
-- Must be idempotent: a redeploy must not drop user data or fail on existing
-- objects. "CREATE ... IF NOT EXISTS" is used wherever Postgres supports it,
-- and role creation + database-level CONNECT grants are wrapped in DO blocks
-- because PostgreSQL requires dynamic SQL for expressions like current_database().

-- ----------------------------------------------------------------------------
-- Tables (docs/hr/schema.md)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS employees (
    employee_id         text PRIMARY KEY,
    cognito_sub         text UNIQUE,
    email               text UNIQUE NOT NULL,
    full_name           text NOT NULL,
    manager_id          text REFERENCES employees(employee_id) ON DELETE RESTRICT,
    legal_entity        text NOT NULL,
    status              text NOT NULL CHECK (status IN ('active', 'terminated')),
    hire_date           date NOT NULL,
    probation_end_date  date NOT NULL
);

CREATE INDEX IF NOT EXISTS employees_manager_id_idx ON employees (manager_id);

CREATE TABLE IF NOT EXISTS salaries (
    employee_id   text PRIMARY KEY REFERENCES employees(employee_id) ON DELETE RESTRICT,
    base_salary   numeric(12,2) NOT NULL CHECK (base_salary >= 0),
    currency      text NOT NULL
);

CREATE TABLE IF NOT EXISTS leave_balances (
    employee_id      text NOT NULL REFERENCES employees(employee_id) ON DELETE RESTRICT,
    leave_type       text NOT NULL CHECK (leave_type IN ('annual', 'sick')),
    remaining_days   numeric(6,1) NOT NULL CHECK (remaining_days >= 0),
    PRIMARY KEY (employee_id, leave_type)
);

CREATE TABLE IF NOT EXISTS leave_requests (
    request_id        text PRIMARY KEY,
    employee_id       text NOT NULL REFERENCES employees(employee_id) ON DELETE RESTRICT,
    leave_type        text NOT NULL CHECK (leave_type IN ('annual', 'sick')),
    start_date        date NOT NULL,
    end_date          date NOT NULL CHECK (end_date >= start_date),
    reason            text NOT NULL,
    status            text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    idempotency_key   text NOT NULL,
    decided_by        text REFERENCES employees(employee_id) ON DELETE RESTRICT,
    decided_at        timestamptz,
    UNIQUE (employee_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS payroll_items (
    employee_id   text NOT NULL REFERENCES employees(employee_id) ON DELETE RESTRICT,
    item_type     text NOT NULL,
    period        text NOT NULL,
    amount        numeric(12,2) NOT NULL CHECK (amount >= 0),
    currency      text NOT NULL,
    PRIMARY KEY (employee_id, item_type, period)
);

-- decision_log is append-only; no HR role may UPDATE or DELETE.
CREATE TABLE IF NOT EXISTS decision_log (
    id                   bigserial PRIMARY KEY,
    at                   timestamptz NOT NULL DEFAULT now(),
    action               text NOT NULL,
    caller_employee_id   text NOT NULL,
    target_employee_id   text,
    allow                boolean NOT NULL,
    reason_code          text NOT NULL,
    agent_id             text NOT NULL,
    session_id           text,
    trace_id             text,
    decided_by_layer     text NOT NULL CHECK (decided_by_layer IN ('policy', 'tool')),
    policy_version       text NOT NULL
);

-- Ensure pre-existing clusters accept 'policy' and 'tool' on decided_by_layer.
DO $$
BEGIN
    ALTER TABLE decision_log
        DROP CONSTRAINT IF EXISTS decision_log_decided_by_layer_check;
    ALTER TABLE decision_log
        ADD CONSTRAINT decision_log_decided_by_layer_check
        CHECK (decided_by_layer IN ('policy', 'tool'));
END
$$;

-- ----------------------------------------------------------------------------
-- Database roles (docs/hr/modules.md "Database roles")
-- ----------------------------------------------------------------------------

DO $$
DECLARE
    r text;
    db text := current_database();
BEGIN
    FOREACH r IN ARRAY ARRAY['hr_reader', 'hr_writer', 'hr_audit', 'hr_identity']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN', r);
        END IF;
        EXECUTE format('GRANT rds_iam TO %I', r);
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', db, r);
    END LOOP;
END
$$;

-- Read tools (hr-payroll, hr-finance, and read actions on hr-ops).
GRANT USAGE ON SCHEMA public TO hr_reader;
GRANT SELECT ON employees, salaries, leave_balances, leave_requests, payroll_items TO hr_reader;

-- Write tool (hr-ops write actions). Inherits read rights and gains INSERT/UPDATE
-- on leave_requests with the narrow column set from the plan.
GRANT USAGE ON SCHEMA public TO hr_writer;
GRANT SELECT ON employees, salaries, leave_balances, leave_requests, payroll_items TO hr_writer;
GRANT INSERT ON leave_requests TO hr_writer;
GRANT UPDATE (status, decided_by, decided_at) ON leave_requests TO hr_writer;

-- Audit sink. Every HR Lambda connects as this role to INSERT one decision
-- row per call. SELECT is withheld on purpose.
GRANT USAGE ON SCHEMA public TO hr_audit;
GRANT INSERT ON decision_log TO hr_audit;
GRANT USAGE ON SEQUENCE decision_log_id_seq TO hr_audit;

-- H3 pre-token Lambda: only the three columns the token claim builder needs.
GRANT USAGE ON SCHEMA public TO hr_identity;
GRANT SELECT (employee_id, cognito_sub, status) ON employees TO hr_identity;

-- Belt-and-braces: nobody in the HR layer may UPDATE or DELETE decision_log.
REVOKE UPDATE, DELETE, TRUNCATE ON decision_log FROM PUBLIC, hr_reader, hr_writer, hr_audit, hr_identity;
