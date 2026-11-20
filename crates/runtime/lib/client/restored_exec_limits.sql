-- Each nondefault policy belongs to the destination, including after an SDK downgrade.
-- Only the transaction that opens admission can create a run for this sandbox.
CREATE TABLE IF NOT EXISTS sandbox_restored_exec_limits (
    sandbox_id INTEGER PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE,
    policy TEXT NOT NULL,
    admitting INTEGER NOT NULL DEFAULT 0 CHECK (admitting IN (0,1))
);
CREATE TRIGGER IF NOT EXISTS restored_exec_limits_guard_run BEFORE INSERT ON run
WHEN EXISTS (SELECT 1 FROM sandbox_restored_exec_limits WHERE sandbox_id = NEW.sandbox_id AND admitting = 0)
BEGIN SELECT RAISE(ABORT, 'saved execution limits require a runtime that can enforce them'); END;
