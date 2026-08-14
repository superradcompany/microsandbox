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

archive_path=$(mktemp "${TMPDIR:-/tmp}/actions-runner.XXXXXX.tar.gz")
trap 'rm -f "${archive_path}"' EXIT

curl --fail --location --retry 5 --output "${archive_path}" "${RUNNER_URL}"
printf '%s  %s\n' "${RUNNER_SHA256}" "${archive_path}" | sha256sum --check --status

# Install the only extra package needed by the KVM jobs before dropping to the
# runner accounts. Pull-request code runs as these users, so they must not have
# Docker access or any sudo path back to the host's root account.
if ! command -v unzip >/dev/null 2>&1; then
  apt-get update
  apt-get install -y unzip
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
  # Restart only services whose account memberships changed.
  if [[ ${privileges_revoked} == true ]]; then
    existing_home=$(getent passwd "${existing_user}" | cut -d: -f6)
    existing_runner_dir="${existing_home}/actions-runner"
    if [[ -x "${existing_runner_dir}/svc.sh" && -f "${existing_runner_dir}/.service" ]]; then
      (
        cd "${existing_runner_dir}"
        ./svc.sh stop
        ./svc.sh start
      )
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
  install -d -o "${runner_user}" -g "${runner_user}" -m 0755 "${runner_dir}"
  if [[ ! -x "${runner_dir}/config.sh" ]]; then
    tar -xzf "${archive_path}" -C "${runner_dir}"
    chown -R "${runner_user}:${runner_user}" "${runner_dir}"
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

  if [[ ! -f "${runner_dir}/.service" ]]; then
    service_name=$(sed -n 's/^SVC_NAME="\([^"]*\)"/\1/p' "${runner_dir}/svc.sh")
    if [[ -n "${service_name}" && -f "/etc/systemd/system/${service_name}" ]]; then
      # Adopt a service left by an interrupted earlier installation. Removing
      # and reinstalling it recreates runsvc.sh and the local .service marker.
      (
        cd "${runner_dir}"
        ./svc.sh uninstall
      )
    fi
    (
      cd "${runner_dir}"
      ./svc.sh install "${runner_user}"
    )
  fi

  (
    cd "${runner_dir}"
    ./svc.sh start
  )

done

echo "provisioned runners ${RUNNER_FIRST}..${RUNNER_LAST} under per-user home directories"
echo "all runners share this host; CI bounds parallel KVM work within each test lane"
