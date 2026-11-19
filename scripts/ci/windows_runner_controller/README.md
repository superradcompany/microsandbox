# Disposable Windows WHP runners

The Check workflow builds one Windows x86_64 test bundle from its checked-out revision, then tests it on fresh Windows 10 and Windows 11 VMs. Each job runs a real WHP guest preflight, the complete Windows filesystem unit suite, and CLI and Rust SDK tests for boot, exec, file access, bind mounts, junction confinement, read-only mounts, stop, and removal. Networking inspection and snapshot regressions can be added when their fixes land.

## Lifecycle and trust

A private Azure Functions timer polls only the configured Check workflow. It admits evaluated, queued jobs with the expected name and exact platform/run/attempt label. Runners have no generic platform or default labels that unrelated jobs could request. Labels route jobs; they do not authorize untrusted code. Fork PRs require GitHub's `all_external_contributors` approval policy. Maintainers must review the exact revision before approving a fork run, including changes to workflows and test scripts. A new revision or rerun has a different run identity and cannot reuse an old lease.

Discovery polls both queued and in-progress workflows because GitHub can return a workflow to queued when its hosted builds finish and only self-hosted jobs remain. Fork discovery also requires the successful GitHub-hosted Windows CLI build from the current attempt's jobs, matching the run and revision. This proves GitHub allowed the prerequisite to execute instead of treating queued status alone as approval. Approval-required, waiting, and completed runs remain ineligible.

Discovery follows every page in each state and deduplicates runs before inspecting jobs, so older queued jobs still reach admission and timeout handling. If an API request fails or a state fills GitHub's 1,000-result filtered-search limit, discovery raises an error without admitting jobs from the incomplete scan. Existing lease progress and cleanup run before discovery and continue on subsequent timer ticks.

The controller never checks out or executes PR code. It creates each VM with a new OS disk from a pinned Marketplace image or a pinned, generalized image version in the dedicated CI resource group's Azure Compute Gallery. Prepared images contain the tools and enabled Hyper-V/WHP features, so jobs skip repeated installation and reboot. Each clone gets fresh SSH host keys and executes a real HLT guest before receiving a single-job runner registration. The Marketplace path still installs and reboots normally, including for VMs already in flight during an image rollout. Builds happen on GitHub-hosted machines. Workers have no compiler checkout, managed identity, cloud credential, App key, signing key, or repository secret. Their job token has only `contents: read`.

The monitored timer checks asynchronous work every 15 seconds. A completed setup stage is saved durably before advancing to the next stage in the same invocation. Pending commands yield without busy-waiting; the Marketplace reboot guard and verified deletion of credential-bearing Run Commands remain mandatory. Lease expiry is checked between immediate transitions as well as before normal reconciliation.

The GitHub App is installed on this repository only, with Administration write for runner registration, Actions write for monitoring and cancelling stranded runs, and Checks write for lifecycle results. Administration permission also allows broad repository administration; this credential must stay in the private control plane. The App key is a Key Vault reference in the Function configuration. Short-lived installation tokens never enter a worker. Only a single-job JIT configuration is staged through protected Azure Run Command parameters, and that command is deleted before the listener starts.

The listener runs as NetworkService with Hyper-V Administrators membership. The service executable and Azure agent state are outside job-writable storage. A job can modify its own machine, so the underlying VM is always destroyed. No disk, runner directory, build cache, or image made from a used worker is reused. The dedicated worker subnet denies inbound access except operator SSH from one configured IPv4 `/32`, denies peer traffic, and blocks Azure metadata access. Workers have no route to production networks. Use only the operator's public SSH key in configuration.

The timer stores credential-free leases in a private blob container. Completed, failed, cancelled, and expired jobs enter cleanup. Before issuing another JIT configuration or completing cleanup, the controller reconciles registrations by the lease's exact job-derived runner name, including registrations whose API response or lease save was lost. Cleanup removes those registrations, the VM, OS disk, NIC, and public IP, retries partial failures, and reports success only after their IDs return 404. A separate tag-based pass runs before lease storage and GitHub access, so expired resources can still be deleted when either dependency is unavailable. Keep the timer running when disabling new admissions.

## Limits and results

- At most two allocated job leases, including orphaned tagged resources. Capacity can be reduced to one.
- A 20-minute GitHub job limit, a maximum 60-minute lease from allocation through cleanup, and a maximum 90-minute admission deadline. Provisioning time counts against the lease. Azure outages can delay deletion, so these limits are not a billing guarantee.
- No warm pool. Idle workers scale to zero; the private Function, storage, and Key Vault have their own ongoing usage costs.
- Setup failure, expired leases, and admission timeout cancel the affected workflow run. Test failure is reported by the Windows job and does not cancel the other Windows lane.
- The App publishes a separate infrastructure check for each OS. A hosted cleanup job verifies both checks belong to the configured App and each lane's executed attempt before Check Summary can pass. Partial reruns reuse a successful lane's original cleanup proof, identified by its evaluated routing label, and require a new proof for every lane that runs again. Missing or skipped lanes cannot qualify.
- Public test output contains only allowlisted stage results, OS version, revision, and test counts. Raw runtime diagnostics remain on the disposable disk and are deleted with it. Do not upload them automatically. Inspect failures privately, then share only redacted, relevant details.

## Private deployment

Provision a dedicated worker resource group and subnet with the isolation above, plus a separate control-plane resource group. The Function's system-assigned identity needs Virtual Machine Contributor and Network Contributor only on the worker group, Key Vault Secrets User only on its vault, and access to its own private lease storage. Prepared images additionally require Reader on their private gallery; the controller must not receive image-publishing permissions. Workers receive no identity. Do not grant the Function permissions over unrelated VMs or production networks.

Use Python 3.12, Functions v4, a monitored timer, and `host.json` from this folder. There is no HTTP trigger. Dependencies and installer hashes are pinned; update them through review before GitHub retires the runner version. Create a source package with:

```sh
python3 scripts/ci/windows_runner_controller/package.py /tmp/windows-ci-controller.zip
az functionapp deployment source config-zip --resource-group "$CONTROL_GROUP" --name "$FUNCTION_APP" --src /tmp/windows-ci-controller.zip --build-remote true
```

Configure these settings privately, never in a workflow, issue, PR, or checked-in file:

| Setting | Purpose |
| --- | --- |
| `WINDOWS_CI_CONFIG` | JSON configuration described below |
| `WINDOWS_CI_REPOSITORY` | Exact `owner/repository`, matching the JSON configuration |
| `GITHUB_APP_ID` | Approved repository-scoped App ID |
| `GITHUB_INSTALLATION_ID` | Installation selected for this repository |
| `GITHUB_APP_PRIVATE_KEY` | Azure Key Vault secret reference containing the PEM |
| `AzureWebJobsStorage` | Private Functions/lease-storage connection string |

`WINDOWS_CI_CONFIG` requires `repository`, numeric `workflow_id`, `subscription`, `resource_group`, `location`, `subnet_id`, `public_key`, `ssh_source`, and `images`. The `images` object has `win10` and `win11` entries. Each entry contains either pinned Marketplace `publisher`, `offer`, `sku`, and `version` fields or a single `id` pointing to an exact numeric gallery image version in the dedicated worker resource group. Mutable `latest` references, disk and snapshot IDs, and galleries outside that group are rejected. Workers use `Standard_D4s_v5` and a fresh 256-GiB Standard SSD. Optional settings are `capacity` (2), `lifetime` (3600 seconds), `queue_timeout` (5400 seconds), `runner_group_id` (1), and `enabled` (false). The subnet must belong to the dedicated worker group. Verify quota, pinned images, client-OS licensing, and runner group availability in the selected subscription before enabling admission.

Deploy with `enabled: false`. Verify the Key Vault reference resolves, the App is installed only on the intended repository, and the timer can read storage and list the worker group. Monitor sanitized control-plane errors and alert on timer failures or tagged resources that survive expiry. The expiry pass is independent of runners, lease storage, and GitHub, but still depends on the Function host and Azure control plane being available.

Before enabling normal runs, exercise both OS lanes, a failing job, cancellation, expiry with an unavailable runner, and a subsequent fresh allocation. Check that the previous runner registration and all four job resources are gone and that a marker from the previous disk is absent. Validate that the job identity cannot read administrator bootstrap/agent files or contact metadata or peers. Unit tests cover the control decisions; these deployment checks verify Azure and Windows behavior.

Set repository variable `WINDOWS_CI_APP_ID` to the approved App ID and `WINDOWS_WHP_CI_ENABLED` to `true` only after qualification. Set private `enabled` to true to admit jobs. To stop new work, set both gates false while leaving the timer deployed for existing cleanup. Roll out controller changes explicitly from a reviewed revision; a PR must never deploy its own privileged controller.

## Prepared Windows images

Build Windows 10 and Windows 11 separately from the pinned Marketplace sources on dedicated builder VMs. Builders must never register a GitHub runner or execute a repository job. Keep the gallery private and let builders consume the existing fleet capacity rather than adding an unbounded temporary fleet.

1. Run `bootstrap.ps1` with the private operator SSH settings, reboot, and wait for the Azure agent to become ready.
2. Run `prepare.ps1` with the base64-encoded WHP probe and launcher source from the reviewed controller revision. This must pass real WHP execution and leave the restricted runner service stopped with manual startup.
3. Run `seal-image.ps1` with the OS platform and source revision. It refuses runner registration, credentials, workspaces, or diagnostics; removes operator keys, SSH host keys, and private setup files; and records the prepared-image contract.
4. Delete the builder's managed Run Commands, then run Windows Sysprep with `/generalize /oobe /shutdown`. Follow Azure's generalized Windows image prerequisites, including the enabled DVD driver. Mark the stopped VM generalized in Azure and capture it into a private Windows, generalized, generation-2 gallery image definition. Pin an explicit image version, wait for replication to succeed, then delete the builder VM, disk, NIC, and public IP.
5. Deploy the compatible controller before changing the private image references. Qualify both OS lanes on fresh clones, including regenerated SSH host keys, stopped runner services before registration, restricted job permissions, runtime tests, and verified deletion. Rebuild images when the pinned tools or Windows base change; never capture a completed job VM.

Retain the original Marketplace references privately for rollback. To roll back to a controller that predates gallery-image support, first drain existing leases and restore those references; the older controller cannot parse gallery references. Prepared image storage persists between jobs, but job VMs and disks remain single-use and scale to zero.

## Local validation

```sh
python3 -m unittest discover -s scripts/ci/windows_runner_controller -v
python3 scripts/ci/windows_runner_controller/package.py /tmp/windows-ci-controller.zip
```

Parse the PowerShell scripts and compile `RunnerLauncher.cs` on Windows. Run the test bundle on both qualified OS versions with its exact revision in `revision.json`. Keep private diagnostics and deployment values outside the repository.
