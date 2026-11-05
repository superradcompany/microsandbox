# Application trust helper

Users download `scripts/msb-trust/msb-trust.sh`. Edit the sources here, then rebuild:

```sh
sh scripts/msb-trust/build.sh
```

`core.sh` handles application selection, dependency reporting, and summaries.
Each file in `apps/` contains one application's setup and help. The build discovers
these files alphabetically and produces a standalone POSIX shell script. No source
files or build tools are needed in the sandbox.

## Add an application

Create `apps/<name>.sh` using lowercase letters, digits, and underscores, starting
with a letter. Use an existing handler as a starting point. Define these functions:

| Function | Purpose |
| --- | --- |
| `<name>_tools` | Print required command names, separated by whitespace. |
| `<name>_packages` | Receive a package manager (`apt-get`, `dnf`, or empty), followed by missing tools. Print the corresponding package names, or nothing for manual setup. |
| `<name>_help` | Print requirements and application-specific instructions. |
| `<name>_configure` | Import the CA at `$CA_CERT`, preserving existing certificates. |

Optional functions are `<name>_description` for the help listing,
`<name>_available` for detection beyond commands on `PATH`, and
`<name>_install_hint` for additional prerequisite instructions.

Keep files limited to function definitions. Handlers run in separate subshells;
explicitly guard fallible operations with `|| fail "useful explanation"` because
batch dispatch disables shell `errexit`. Use `progress` for success messages so
batch runs can print one combined summary. Never install packages automatically.

Rebuild and include both the source and generated script in your change. CI runs
`sh scripts/msb-trust/build.sh --check` to reject stale output or missing required
functions. Validate setup, repeat runs, and failures against the real application.
