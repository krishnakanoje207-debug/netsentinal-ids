#!/bin/sh
# Reissue the Wazuh API's certificate for the name the responder dials, and export
# its public half for the responder to trust.
#
#   cd infra && sh wazuh/api-cert.sh
#
# The manager makes a self-signed certificate on its first start that names only
# localhost, so a client on the backplane dialling wazuh.manager could only stop
# checking it or fail. This replaces it with one that also names wazuh.manager,
# restarts the manager so its API serves it, and copies server.crt - never the key -
# to wazuh/api-tls/api-ca.crt (gitignored), which compose mounts into the API and
# the responder as NETSENTINEL_WAZUH_CA_FILE. Rerun it when the certificate expires.
set -eu
cd "$(dirname "$0")/.."

ssl=/var/ossec/api/configuration/ssl
manager="docker compose --profile hids exec -T wazuh.manager"

$manager sh -c "
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout $ssl/server.key -out $ssl/server.crt \
    -subj /CN=wazuh.manager \
    -addext 'subjectAltName=DNS:wazuh.manager,DNS:localhost,IP:127.0.0.1' 2>/dev/null &&
  chown wazuh:wazuh $ssl/server.key $ssl/server.crt &&
  chmod 400 $ssl/server.key $ssl/server.crt"
docker compose --profile hids restart wazuh.manager

mkdir -p wazuh/api-tls
$manager cat $ssl/server.crt > wazuh/api-tls/api-ca.crt
echo "wrote wazuh/api-tls/api-ca.crt; now: docker compose --profile response up -d responder"
