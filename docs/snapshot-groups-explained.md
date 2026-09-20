# Microsandbox snapshots: groups, checkpoints, and the head

This describes the snapshot-group implementation on the development stack, not an already released CLI.

## Start with the snapshot

A snapshot is a saved point you can use to create another sandbox:

```text
Running sandbox
      |
      +-- disk snapshot ----> new VM boots from the saved disk
      |
      +-- full snapshot ----> new VM resumes saved RAM, CPUs, devices, and disk
```

Disk snapshots also work when the source is paused or stopped. Full snapshots require resident execution state: a running or user-paused VM. Each capture produces a new immutable snapshot, even when unchanged disk layers or RAM objects are reused. Exporting a snapshot packages it as a `.msb` archive; loading an archive installs it without starting a VM.

## A group gives those saved points a local home

A **group** is a namespace containing snapshots and a selected **head**. Member names such as `cp01` are meaningful inside their group. Each snapshot also keeps its portable `snap_...` ID. A new group imported from competing branches can temporarily have no selected head; choose one explicitly before restoring by the bare group name.

```text
~/.microsandbox/snapshots/
|
+-- worker/
|   +-- group.json                 head = snap_B
|   +-- snap_A/
|   |   +-- snapshot.json          ID, parent, disk/state references
|   |   +-- group-member.json      name = cp01
|   |   +-- layers/...             disk-only payload
|   +-- snap_B/
|       +-- snapshot.json          parent = snap_A
|       +-- group-member.json      name = cp02
|       +-- checkpoint/...         full checkpoint payload, when captured full
|
+-- imported/
    +-- group.json
    +-- snap_A/...                 a separate local copy of the same snapshot
```

IDs above are shortened for readability. A disk-only member uses `layers/`; a full member uses `checkpoint/` with its disk layers, RAM objects, and execution/device state. Optional `metadata.json` stores labels.

Groups do not magically make random IDs collision-proof. They keep local addresses separate. Within one group, the same ID with the same descriptor is reusable; the same ID with different descriptor bytes is rejected. A name already used by another member is also rejected. Nothing is silently overwritten. If a global ID resolves to multiple local copies, use the group-qualified address instead.

## Create and restore

```bash
msb create alpine --name worker --memory 512M

# Group defaults to the source sandbox's name: worker.
msb snapshot create cp01 --sandbox worker --full
msb snapshot create cp02 --sandbox worker --full

# A bare group selects its head, currently cp02.
msb restore worker --name latest --forked

# A qualified name selects an exact checkpoint.
msb restore worker:cp01 --name earlier --forked

# You can choose a different group, or let a member name be generated.
msb snapshot create --sandbox worker --group experiments --full
```

`--forked` shares clean restored RAM pages using copy-on-write; child writes remain private. It does not change which snapshot is selected. Omit `--full` at capture for a disk-only snapshot, and omit `--forked` when cold-booting disk state.

## The head moves forward, not sideways by surprise

Snapshots record their actual source ancestry. Neither timestamps, import order, nor an export's `--since` base defines that ancestry.

```text
worker:cp01 ---- worker:cp02 ---- worker:cp03  <- head
                     \
                      +-------- worker:experiment
```

The rules are small:

- Empty group: a single capture or import initializes its head. A batch selects its one provably newest tip, if there is one.
- Known descendant of the current head: advance automatically.
- Same member, older member, sibling, unrelated history, or missing ancestry: keep the current head. The capture/import still succeeds.
- Explicit selection: choose any complete installed member, including an older one.

```bash
msb snapshot head worker             # Read the current head ID
msb snapshot head worker:experiment  # Explicitly choose the other branch
msb snapshot head worker:cp01        # Explicitly rewind
```

There is no special `main` branch. The head is a selected snapshot, not a rule for guessing which future branch is preferred.

### What if two separate operations publish siblings concurrently?

```text
                    +---- snapshot A
head: cp02 ---------+
                    +---- snapshot B

A publishes first:  head cp02 -> A
B publishes next:   B is A's sibling, so head stays A

Result: both snapshots exist. Only the first head update wins.
```

Publication checks and head replacement share a per-group lock. The losing sibling is not discarded or reported as a failed capture. If you want B, select it explicitly. Two captures of the *same* source are serialized and record a parent chain; they are not treated as sibling captures.

A **single batch containing both siblings** is different: neither argument order nor which file finishes first chooses the head. An existing group retains its head; a new group imports both members with no selected head. Then use `msb snapshot head worker:<member>` to choose.

## Move a history to another machine

```bash
# On the source machine:
mkdir -p checkpoints
msb snapshot save worker:cp01 checkpoints/cp01.msb
msb snapshot save worker:cp02 checkpoints/cp02.msb --since worker:cp01

# On the destination machine:
msb snapshot load checkpoints/*.msb --group received
msb restore received --name restored --forked
```

The shell expands `*.msb` into archive paths. Their order and filenames do not determine ancestry or load order. You can also list them explicitly, in any order:

```bash
msb snapshot load checkpoints/cp02.msb checkpoints/cp01.msb --group received
```

Loading unpacks each supplied archive once, matches omitted disk layers and RAM objects to the available payloads, and validates the reconstructed snapshots before publishing members. It looks in the supplied batch first, then the explicitly selected destination group. This works for disk-only and full incremental archives. No intermediate VM runs.

The same automatic lookup works when archives arrive separately:

```bash
msb snapshot load checkpoints/cp01.msb --group received
msb snapshot load checkpoints/cp02.msb --group received
```

`--base` is only needed when the missing data is elsewhere, such as `--base another-group:cp01` or `--base /path/to/baseline.msb`. It supplies data; it does not define ancestry or select the group head. An external archive supplied as `--base` must be standalone; include dependent archives in the batch instead. Missing dependencies and conflicting IDs, names, or duplicate labels fail before publishing any incoming members.

Current development limitation: disk-only captures reassign layer IDs, so `--since` between successive disk-only captures can reject the base. Use standalone disk-only exports for that workflow until capture identity preservation is fixed. Full-checkpoint incremental imports were live-tested successfully; the batch loader also handles dependency-correct disk-only archives.

`--since` omits disk layers and reusable RAM objects supplied by the explicit base. Loading reconstructs a complete owned snapshot; the target does not depend on replaying earlier VMs. Each archive still includes the target's complete memory map and CPU/device state. The `.msb` archive does not contain a local group's mutable head file: its declared archive head is the import candidate, and the receiving group applies the rules above.

Loading without `--group` creates one fresh generated group for the whole batch. The CLI prints a digest and installed artifact **path** for each input archive head, in input order. With one archive, the final line remains its installed path. With several archives, the final path is not necessarily the selected group head; use the group selector or `msb snapshot head received` instead. Repeating the same snapshot installs it only once.

The destination directory is now an explicit `--dest DIR` option, leaving positional arguments for archive paths. Existing snapshot/archive formats are unchanged, including legacy readers.

Importing an old checkpoint does not rewind an existing group. To deliberately select the imported archive's head:

```bash
msb snapshot load checkpoints/cp01.msb --group received --set-head
```

For a batch, `--set-head` requires one unambiguous tip; it refuses competing tips rather than picking the last argument. Load those members without `--set-head`, then select the one you want.

Missing historical checkpoints are okay when payload dependencies are complete. But a missing parent may prevent proving a fast-forward. Filling a history hole does not retrospectively select some other retained tip; select that tip explicitly or import it again once its ancestry is known.

Direct archive capture (`snapshot create --output PATH`, or `-o PATH`) and direct archive restore still skip installed snapshot directories. `msb branch` still creates a local child without publishing a durable snapshot. Neither operation implicitly moves a group's head; a later explicit capture can join a group using the child's recorded ancestry.
