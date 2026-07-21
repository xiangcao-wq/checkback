#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'Run this installer as root (for example: sudo ./install-geoip.sh)\n' >&2
  exit 1
fi

readonly database_url='https://github.com/sapics/ip-location-db/releases/download/latest/iptoasn-country.mmdb'
readonly expected_sha256='5b15d2e30f92ce0fe7d3cbe17dc787bb5ae710b95d09f24fcb70541be55e2cea'
readonly install_root='/etc/checkback/geoip'
readonly install_path="${install_root}/iptoasn-country.mmdb"
temp_dir="$(mktemp -d)"
trap 'rm -rf --one-file-system -- "${temp_dir}"' EXIT

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --output "${temp_dir}/iptoasn-country.mmdb" \
  "${database_url}"
printf '%s  %s\n' "${expected_sha256}" "${temp_dir}/iptoasn-country.mmdb" | sha256sum --check --status
install -d -m 0755 -o root -g root "${install_root}"
install -m 0644 -o root -g root "${temp_dir}/iptoasn-country.mmdb" "${install_path}"
printf 'Installed verified GeoIP country database at %s\n' "${install_path}"
