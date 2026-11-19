-- Private tree ownership survives both interruption before parking and interruption
-- after the catalog transaction that restores or publishes the public name.
CREATE TABLE IF NOT EXISTS sandbox_replacement_storage (
    name TEXT PRIMARY KEY,
    token TEXT NOT NULL UNIQUE
);
-- Older clients reject unknown migration versions. These auxiliary objects only
-- participate while a replacement owns a name. The parked row keeps its FKs.
CREATE TABLE IF NOT EXISTS sandbox_replacement (
    name TEXT PRIMARY KEY,
    original INTEGER NOT NULL UNIQUE REFERENCES sandbox(id),
    token TEXT NOT NULL UNIQUE,
    had_directory INTEGER NOT NULL,
    candidate INTEGER,
    admitting INTEGER NOT NULL DEFAULT 0,
    published INTEGER NOT NULL DEFAULT 0
);
CREATE TRIGGER IF NOT EXISTS replacement_guard_update BEFORE UPDATE ON sandbox
WHEN EXISTS (SELECT 1 FROM sandbox_replacement WHERE original = OLD.id)
BEGIN SELECT RAISE(ABORT, 'sandbox is retained for replacement recovery'); END;
CREATE TRIGGER IF NOT EXISTS replacement_guard_delete BEFORE DELETE ON sandbox
WHEN EXISTS (SELECT 1 FROM sandbox_replacement WHERE original = OLD.id)
BEGIN SELECT RAISE(ABORT, 'sandbox is retained for replacement recovery'); END;
CREATE TRIGGER IF NOT EXISTS replacement_guard_insert BEFORE INSERT ON sandbox
WHEN EXISTS (SELECT 1 FROM sandbox_replacement WHERE name = NEW.name AND published = 0 AND admitting = 0)
BEGIN SELECT RAISE(ABORT, 'sandbox name is reserved for replacement recovery'); END;
CREATE TRIGGER IF NOT EXISTS replacement_guard_rename BEFORE UPDATE OF name ON sandbox
WHEN EXISTS (SELECT 1 FROM sandbox_replacement WHERE name = NEW.name AND published = 0 AND original != NEW.id)
AND OLD.name != NEW.name
BEGIN SELECT RAISE(ABORT, 'sandbox name is reserved for replacement recovery'); END;
CREATE TRIGGER IF NOT EXISTS replacement_record_candidate AFTER INSERT ON sandbox
WHEN EXISTS (SELECT 1 FROM sandbox_replacement WHERE name = NEW.name AND admitting = 1)
BEGIN UPDATE sandbox_replacement SET candidate = NEW.id, admitting = 0 WHERE name = NEW.name; END;
CREATE TRIGGER IF NOT EXISTS replacement_record_publication AFTER UPDATE OF creation_state ON sandbox
WHEN OLD.creation_state IS NOT NULL AND NEW.creation_state IS NULL AND NEW.status = 'Running'
BEGIN UPDATE sandbox_replacement SET published = 1 WHERE candidate = NEW.id; END;

-- An explicit restart of a retained ephemeral sandbox restores cleanup only after
-- it reaches Running. A failed restart can therefore be retried.
CREATE TABLE IF NOT EXISTS sandbox_replacement_ephemeral (
    original INTEGER PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE
);
CREATE TRIGGER IF NOT EXISTS replacement_resume_ephemeral AFTER UPDATE OF status ON sandbox
WHEN NEW.status = 'Running' AND OLD.status = 'Starting' AND EXISTS
    (SELECT 1 FROM sandbox_replacement_ephemeral WHERE original = NEW.id)
BEGIN
    UPDATE sandbox SET ephemeral = 1 WHERE id = NEW.id;
    DELETE FROM sandbox_replacement_ephemeral WHERE original = NEW.id;
END;
