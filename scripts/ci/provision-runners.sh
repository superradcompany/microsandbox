#!/usr/bin/env bash

set -euo pipefail

# By default, provision eight additional repository-scoped GitHub Actions
# runners on the existing Ubuntu host, bringing runner01..runner12 online.
# Each runner gets a distinct unprivileged Unix user and work tree so concurrent
# checkouts and per-user ~/.microsandbox state cannot collide.
#
# Run as root with a short-lived repository registration token:
#   sudo REPOSITORY_URL=https://github.com/OWNER/REPO \
#     RUNNER_REGISTRATION_TOKEN=... scripts/ci/provision-runners.sh

if [[ ${EUID} -ne 0 ]]; then
  echo "this script must run as root" >&2
  exit 1
fi

: "${REPOSITORY_URL:?set REPOSITORY_URL to the GitHub repository URL}"
: "${RUNNER_REGISTRATION_TOKEN:?set RUNNER_REGISTRATION_TOKEN to a short-lived runner token}"

RUNNER_VERSION=${RUNNER_VERSION:-2.336.0}
RUNNER_SHA256=${RUNNER_SHA256:-04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d}
RUNNER_ARCHIVE=${RUNNER_ARCHIVE:-actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz}
RUNNER_URL=${RUNNER_URL:-https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_ARCHIVE}}
RUNNER_LABELS=${RUNNER_LABELS:-self-hosted-ubuntu-2404-x64}
RUNNER_PREFIX=${RUNNER_PREFIX:-ci-runner-ubuntu-2404-x64-runner}
RUNNER_USER_PREFIX=${RUNNER_USER_PREFIX:-runner}
RUNNER_FIRST=${RUNNER_FIRST:-5}
RUNNER_LAST=${RUNNER_LAST:-12}

if (( RUNNER_FIRST < 1 || RUNNER_LAST < RUNNER_FIRST )); then
  echo "invalid runner range: ${RUNNER_FIRST}..${RUNNER_LAST}" >&2
  exit 1
fi

repository_path=${REPOSITORY_URL#https://github.com/}
repository_path=${repository_path%.git}
repository_path=${repository_path%/}
if [[ ! ${repository_path} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "unsupported GitHub repository URL: ${REPOSITORY_URL}" >&2
  exit 1
fi
runner_service_scope=${repository_path//\//-}

runner_services_for() {
  local runner_user=$1
  local runner_dir=$2
  local service_name

  while read -r service_name _; do
    if [[ -z ${service_name} ]]; then
      continue
    fi

    if [[ $(systemctl show --property=User --value "${service_name}") == "${runner_user}" ]] &&
      [[ $(systemctl show --property=WorkingDirectory --value "${service_name}") == "${runner_dir}" ]]; then
      printf '%s\n' "${service_name}"
    fi
  done < <(systemctl list-unit-files --type=service --no-legend 'actions.runner.*.service')
}

archive_path=$(mktemp "${TMPDIR:-/tmp}/actions-runner.XXXXXX.tar.gz")
unit_template_path=$(mktemp "${TMPDIR:-/tmp}/actions-runner-unit.XXXXXX.service")
trap 'rm -f "${archive_path}" "${unit_template_path}"' EXIT

curl --fail --location --retry 5 --output "${archive_path}" "${RUNNER_URL}"
printf '%s  %s\n' "${RUNNER_SHA256}" "${archive_path}" | sha256sum --check --status
chmod 0644 "${archive_path}"

# Install the extra packages needed by the KVM jobs before dropping to the
# runner accounts. Skopeo exports test images without access to the privileged
# Docker daemon. Pull-request code must not have Docker or sudo access.
if ! command -v unzip >/dev/null 2>&1 || ! command -v skopeo >/dev/null 2>&1; then
  apt-get update
  apt-get install -y skopeo unzip
fi
rm -f /etc/sudoers.d/actions-runner-apt

# Revoke the legacy privileges from every runnerNN account, including the
# original runner01..runner04 users that predate this provisioner.
while IFS=: read -r existing_user _; do
  if [[ ${existing_user} != "${RUNNER_USER_PREFIX}"* ]]; then
    continue
  fi

  runner_suffix=${existing_user#"${RUNNER_USER_PREFIX}"}
  if [[ ! ${runner_suffix} =~ ^[0-9]+$ ]]; then
    continue
  fi

  privileges_revoked=false
  for privileged_group in docker actions-runner; do
    if id -nG "${existing_user}" | tr ' ' '\n' | grep -Fxq "${privileged_group}"; then
      gpasswd --delete "${existing_user}" "${privileged_group}" >/dev/null
      privileges_revoked=true
    fi
  done

  # A running service retains its old supplementary groups until it restarts.
  # Discover it through root-controlled systemd metadata rather than trusting
  # the runner-writable svc.sh or .service files.
  if [[ ${privileges_revoked} == true ]]; then
    existing_home=$(getent passwd "${existing_user}" | cut -d: -f6)
    existing_runner_dir="${existing_home}/actions-runner"
    mapfile -t existing_services < <(runner_services_for "${existing_user}" "${existing_runner_dir}")
    if (( ${#existing_services[@]} > 1 )); then
      echo "multiple services found for ${existing_user}: ${existing_services[*]}" >&2
      exit 1
    fi
    if (( ${#existing_services[@]} == 1 )); then
      systemctl restart "${existing_services[0]}"
    fi
  fi
done < <(getent passwd)

for index in $(seq "${RUNNER_FIRST}" "${RUNNER_LAST}"); do
  suffix=$(printf '%02d' "${index}")
  runner_user="${RUNNER_USER_PREFIX}${suffix}"
  runner_name="${RUNNER_PREFIX}${suffix}"

  if ! id "${runner_user}" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash --groups kvm "${runner_user}"
  fi
  usermod --append --groups kvm "${runner_user}"

  runner_home=$(getent passwd "${runner_user}" | cut -d: -f6)
  runner_dir="${runner_home}/actions-runner"
  if [[ -L ${runner_dir} ]]; then
    echo "refusing to use symlinked runner directory: ${runner_dir}" >&2
    exit 1
  fi
  install -d -o "${runner_user}" -g "${runner_user}" -m 0755 "${runner_dir}"
  if [[ ! -x "${runner_dir}/config.sh" || ! -f "${runner_dir}/.runner" ]]; then
    runuser -u "${runner_user}" -- tar -xzf "${archive_path}" -C "${runner_dir}"
  fi

  if [[ ! -f "${runner_dir}/.runner" ]]; then
    runuser -u "${runner_user}" -- "${runner_dir}/config.sh" \
      --url "${REPOSITORY_URL}" \
      --token "${RUNNER_REGISTRATION_TOKEN}" \
      --name "${runner_name}" \
      --labels "${RUNNER_LABELS}" \
      --work _work \
      --unattended
  fi

  if [[ ! -x "${runner_dir}/runsvc.sh" ]]; then
    runuser -u "${runner_user}" -- \
      install -m 0755 "${runner_dir}/bin/runsvc.sh" "${runner_dir}/runsvc.sh"
  fi

  service_name="actions.runner.${runner_service_scope}.${runner_name}.service"
  unit_path="/etc/systemd/system/${service_name}"
  mapfile -t runner_services < <(runner_services_for "${runner_user}" "${runner_dir}")
  if (( ${#runner_services[@]} > 1 )); then
    echo "multiple services found for ${runner_user}: ${runner_services[*]}" >&2
    exit 1
  fi
  if (( ${#runner_services[@]} == 1 )) && [[ ${runner_services[0]} != "${service_name}" ]]; then
    echo "unexpected service for ${runner_user}: ${runner_services[0]}" >&2
    exit 1
  fi
  if [[ -L ${unit_path} ]]; then
    echo "refusing to replace symlinked systemd unit: ${unit_path}" >&2
    exit 1
  fi

  cat > "${unit_template_path}" <<EOF
[Unit]
Description=GitHub Actions Runner (${runner_service_scope}.${runner_name})
After=network-online.target

[Service]
ExecStart=${runner_dir}/runsvc.sh
User=${runner_user}
WorkingDirectory=${runner_dir}
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=5min

[Install]
WantedBy=multi-user.target
EOF

  unit_changed=false
  if [[ ! -f ${unit_path} ]] || ! cmp --silent "${unit_template_path}" "${unit_path}"; then
    install -o root -g root -m 0644 "${unit_template_path}" "${unit_path}"
    systemctl daemon-reload
    unit_changed=true
  else
    chown root:root "${unit_path}"
    chmod 0644 "${unit_path}"
  fi

  printf '%s\n' "${service_name}" |
    runuser -u "${runner_user}" -- tee "${runner_dir}/.service" >/dev/null
  systemctl enable "${service_name}"
  if [[ ${unit_changed} == true ]] && systemctl is-active --quiet "${service_name}"; then
    systemctl restart "${service_name}"
  else
    systemctl start "${service_name}"
  fi

done

echo "provisioned runners ${RUNNER_FIRST}..${RUNNER_LAST} under per-user home directories"
echo "all runners share this host; CI bounds parallel KVM work within each test lane"
