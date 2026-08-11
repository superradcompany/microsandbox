#!/usr/bin/env bash

set -euo pipefail

# By default, provision eight additional repository-scoped GitHub Actions
# runners on the existing Ubuntu host, bringing runner01..runner12 online.
# Each runner gets a distinct Unix user and work tree so concurrent checkouts
# and per-user ~/.microsandbox state cannot collide.
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

sudoers_tmp=$(mktemp "${TMPDIR:-/tmp}/microsandbox-actions-runners.XXXXXX")
trap 'rm -f "${archive_path}" "${sudoers_tmp}"' EXIT

# Match the existing runner01..runner04 host policy. Group membership grants
# KVM and Docker access, while sudo remains restricted to apt-get.
groupadd --force actions-runner
printf '%%actions-runner ALL=(root) NOPASSWD: /usr/bin/apt-get\n' > "${sudoers_tmp}"
chmod 0440 "${sudoers_tmp}"
visudo -c -f "${sudoers_tmp}"
install -o root -g root -m 0440 "${sudoers_tmp}" /etc/sudoers.d/actions-runner-apt

for index in $(seq "${RUNNER_FIRST}" "${RUNNER_LAST}"); do
  suffix=$(printf '%02d' "${index}")
  runner_user="${RUNNER_USER_PREFIX}${suffix}"
  runner_name="${RUNNER_PREFIX}${suffix}"

  if ! id "${runner_user}" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash --groups kvm,docker,actions-runner "${runner_user}"
  fi
  usermod --append --groups kvm,docker,actions-runner "${runner_user}"

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
echo "all runners share this host; CI limits the two compiler-heavy lanes to 12 jobs each"
