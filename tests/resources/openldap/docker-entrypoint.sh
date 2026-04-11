#!/usr/bin/env bash

set -e
set -x

SLAPD_KEY="/etc/ssl/private/slapd.key"
SLAPD_CERT="/etc/ssl/certs/slapd.crt"
SLAPD_DATA="/var/lib/ldap"
SLAPD_CONF="/etc/ldap/slapd.d"
CA_KEY="/etc/ssl/private/example.key"
CA_CERT="/usr/local/share/ca-certificates/example.crt"
LDIF="/etc/ldap/bootstrap-ldif"
CERT_TEMPLATES="/etc/ldap/tls-templates"

# Required by conf.ldif (olcPidFile / olcArgsFile)
mkdir -p /var/run/slapd

# Remove any existing data / config from the base image
rm -rf "${SLAPD_CONF:?}"/*
rm -rf "${SLAPD_DATA:?}"/*

mkdir -p /usr/local/share/ca-certificates

# Generate the CA cert
certtool --generate-privkey > ${CA_KEY}
certtool --generate-self-signed \
  --load-privkey ${CA_KEY} \
  --template ${CERT_TEMPLATES}/ca.info \
  --outfile ${CA_CERT}

update-ca-certificates

# Generate the slapd cert
certtool --generate-privkey \
  --bits 2048 \
  --outfile ${SLAPD_KEY}
certtool --generate-certificate \
  --load-privkey ${SLAPD_KEY} \
  --load-ca-certificate ${CA_CERT} \
  --load-ca-privkey ${CA_KEY} \
  --template ${CERT_TEMPLATES}/slapd.info \
  --outfile ${SLAPD_CERT}

# Permissions for the cert key
adduser openldap ssl-cert
chgrp ssl-cert ${SLAPD_KEY}
chmod g+r ${SLAPD_KEY}
chmod o-r ${SLAPD_KEY}

# Bootstrap configuration
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${LDIF}/conf.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${LDIF}/modules.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${LDIF}/memberof.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${LDIF}/vlv.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${LDIF}/syncrepl.ldif

# Add the base DN
slapadd -F ${SLAPD_CONF} <<EOM
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
EOM

# Import test data (quick mode for bulk load)
slapadd -q -F ${SLAPD_CONF} -l ${LDIF}/data.ldif
slapadd -q -F ${SLAPD_CONF} -l ${LDIF}/data-group.ldif

chown -R openldap:openldap ${SLAPD_CONF}
chown -R openldap:openldap ${SLAPD_DATA}
chown openldap:openldap /var/run/slapd

# Copy certs to the volume mount if provided.
# ca.crt     - needed by the PHP test runner to validate TLS connections to OpenLDAP
# slapd.crt  - used by the PHP LDAP server (ldap-server.php) for TLS
# slapd.key  - used by the PHP LDAP server (ldap-server.php) for TLS
if [ -d "/cert-output" ]; then
    cp ${CA_CERT} /cert-output/ca.crt
    cp ${SLAPD_CERT} /cert-output/slapd.crt
    cp ${SLAPD_KEY} /cert-output/slapd.key
    chmod 644 /cert-output/slapd.key
fi

# Start slapd in the background so we can apply ordering.ldif via ldapmodify
/usr/sbin/slapd \
    -d 0 \
    -u openldap \
    -g openldap \
    -F ${SLAPD_CONF} \
    -h "ldap:/// ldaps:/// ldapi:///" &
SLAPD_PID=$!

# Wait for slapd to be ready
for i in $(seq 1 30); do
    ldapwhoami -H ldapi:/// -x && break
    sleep 1
done

# Apply ordering rules — requires a running slapd with ldapi access
ldapmodify -Y EXTERNAL -H ldapi:/// -f ${LDIF}/ordering.ldif

# Keep the container alive by waiting on slapd
wait ${SLAPD_PID}
