-- Created only for destinations with deferred new-command inputs. Catalog readers and
-- ordinary runs do not need to know about this table. Deleting a destination deletes its guard.
CREATE TABLE IF NOT EXISTS sandbox_command_bindings (
    sandbox_id INTEGER PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE,
    requirements TEXT NOT NULL,
    admitting INTEGER NOT NULL DEFAULT 0 CHECK (admitting IN (0,1))
);
CREATE TRIGGER IF NOT EXISTS command_bindings_guard_run BEFORE INSERT ON run
WHEN EXISTS (SELECT 1 FROM sandbox_command_bindings WHERE sandbox_id = NEW.sandbox_id AND admitting = 0)
BEGIN SELECT RAISE(ABORT, 'sandbox has outstanding command bindings and needs a runtime that supports them'); END;
