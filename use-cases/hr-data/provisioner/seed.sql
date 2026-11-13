-- Demo seed for the HR database. Spec: docs/hr/schema.md "Demo seed".
-- Applied by provisioner/handler.py ONLY when platform.yaml sets
--   use_cases.hr-data.seed: true
--
-- Guard rule from the spec:
--   "The script upserts only the nine ids below. If any other `employee_id`
--    is already present, it exits with an error and writes nothing."
-- The handler enforces the guard before calling this file, because Data API
-- cannot roll back across separate ExecuteStatement calls. The guard here
-- is a second net inside a single transaction.

-- Guard: any row outside the allowed set is a hard failure. The assertion
-- aborts the transaction, which rolls back the upserts below.
DO $$
DECLARE
    stray_count int;
    allowed_ids text[] := ARRAY['M1','E1','E2','P1','R1','R2','R3','R4','X1'];
BEGIN
    SELECT count(*) INTO stray_count
    FROM employees
    WHERE employee_id <> ALL (allowed_ids);
    IF stray_count > 0 THEN
        RAISE EXCEPTION 'seed refused: % employee row(s) outside the demo set are already present', stray_count
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
END
$$;

-- employees. full_name equals employee_id for the demo seed (docs/hr/schema.md).
-- Hire date is 2020-01-01 for everyone except P1 (2026-09-01). legal_entity is
-- 'demo'. Emails are {id}@example.com. cognito_sub stays NULL until a real
-- sign-in is mapped in a test.
INSERT INTO employees (employee_id, email, full_name, manager_id, legal_entity, status, hire_date, probation_end_date) VALUES
    ('M1', 'M1@example.com', 'M1', NULL, 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('E1', 'E1@example.com', 'E1', 'M1', 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('E2', 'E2@example.com', 'E2', 'M1', 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('P1', 'P1@example.com', 'P1', 'M1', 'demo', 'active',     '2026-09-01', '2027-03-01'),
    ('R1', 'R1@example.com', 'R1', 'E1', 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('R2', 'R2@example.com', 'R2', 'E1', 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('R3', 'R3@example.com', 'R3', 'E1', 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('R4', 'R4@example.com', 'R4', 'E1', 'demo', 'active',     '2020-01-01', '2020-07-01'),
    ('X1', 'X1@example.com', 'X1', 'M1', 'demo', 'terminated', '2020-01-01', '2020-07-01')
ON CONFLICT (employee_id) DO UPDATE SET
    email              = EXCLUDED.email,
    full_name          = EXCLUDED.full_name,
    manager_id         = EXCLUDED.manager_id,
    legal_entity       = EXCLUDED.legal_entity,
    status             = EXCLUDED.status,
    hire_date          = EXCLUDED.hire_date,
    probation_end_date = EXCLUDED.probation_end_date;

-- salaries (one current row per employee).
INSERT INTO salaries (employee_id, base_salary, currency) VALUES
    ('M1', 10000.00, 'USD'),
    ('E1',  5000.00, 'USD'),
    ('E2',  4500.00, 'USD'),
    ('P1',  4000.00, 'USD'),
    ('R1',  3000.00, 'USD'),
    ('R2',  3100.00, 'USD'),
    ('R3',  3200.00, 'USD'),
    ('R4',  3300.00, 'USD'),
    ('X1',  2000.00, 'USD')
ON CONFLICT (employee_id) DO UPDATE SET
    base_salary = EXCLUDED.base_salary,
    currency    = EXCLUDED.currency;

-- leave_balances: every employee gets annual 14, sick 10.
INSERT INTO leave_balances (employee_id, leave_type, remaining_days) VALUES
    ('M1', 'annual', 14.0), ('M1', 'sick', 10.0),
    ('E1', 'annual', 14.0), ('E1', 'sick', 10.0),
    ('E2', 'annual', 14.0), ('E2', 'sick', 10.0),
    ('P1', 'annual', 14.0), ('P1', 'sick', 10.0),
    ('R1', 'annual', 14.0), ('R1', 'sick', 10.0),
    ('R2', 'annual', 14.0), ('R2', 'sick', 10.0),
    ('R3', 'annual', 14.0), ('R3', 'sick', 10.0),
    ('R4', 'annual', 14.0), ('R4', 'sick', 10.0),
    ('X1', 'annual', 14.0), ('X1', 'sick', 10.0)
ON CONFLICT (employee_id, leave_type) DO UPDATE SET
    remaining_days = EXCLUDED.remaining_days;

-- payroll_items: one telephone row for E1 only. A denied caller must not learn
-- that no other row exists, which is docs/hr/tools.md's job (the tool returns
-- `amount: null` not `NOT_AUTHORIZED` for a self call with no row).
INSERT INTO payroll_items (employee_id, item_type, period, amount, currency) VALUES
    ('E1', 'telephone', '2026-10', 25.00, 'USD')
ON CONFLICT (employee_id, item_type, period) DO UPDATE SET
    amount   = EXCLUDED.amount,
    currency = EXCLUDED.currency;
