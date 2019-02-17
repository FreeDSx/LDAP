#!/usr/bin/env bash

# Adapted from the ruby-net-ldap setup scripts:
#     https://github.com/ruby-ldap/ruby-net-ldap
#
# Which seemed to originate from github-ldap integration scripts:
#     https://github.com/github/github-ldap
#
# Adapted for the needs of this library.

set -e
set -x

RESOURCE_PATH="./tests/resources/openldap"
SLAPD_KEY="/etc/ssl/private/slapd.key"
SLAPD_CERT="/etc/ssl/certs/slapd.crt"
SLAPD_DATA="/var/lib/ldap"
SLAPD_CONF="/etc/ldap/slapd.d"
CA_KEY="/etc/ssl/private/example.key"
CA_CERT="/usr/local/share/ca-certificates/example.crt"

service slapd stop

# Remove existing data, reconfigure...
[[ -e ${SLAPD_DATA}/DB_CONFIG ]] && cp -v ${SLAPD_DATA}/DB_CONFIG ./DB_CONFIG
rm -rf ${SLAPD_CONF}/*
rm -rf ${SLAPD_DATA}/*
[[ -e ./DB_CONFIG ]] && cp -v ./DB_CONFIG ${SLAPD_DATA}/DB_CONFIG

# Generate the CA cert
certtool --generate-privkey > ${CA_KEY}
certtool --generate-self-signed \
  --load-privkey ${CA_KEY} \
  --template ${RESOURCE_PATH}/cert/ca.info \
  --outfile ${CA_CERT}

update-ca-certificates

# Generate the actual cert used by slapd...
certtool --generate-privkey \
  --bits 2048 \
  --outfile ${SLAPD_KEY}
certtool --generate-certificate \
  --load-privkey ${SLAPD_KEY} \
  --load-ca-certificate ${CA_CERT} \
  --load-ca-privkey ${CA_KEY} \
  --template ${RESOURCE_PATH}/cert/slapd.info \
  --outfile ${SLAPD_CERT}

# Needed permission changes for the cert...
adduser openldap ssl-cert
chgrp ssl-cert ${SLAPD_KEY}
chmod g+r ${SLAPD_KEY}
chmod o-r ${SLAPD_KEY}

# Some initial imports...
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${RESOURCE_PATH}/ldif/conf.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${RESOURCE_PATH}/ldif/modules.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${RESOURCE_PATH}/ldif/memberof.ldif
slapadd -F ${SLAPD_CONF} -b "cn=config" -l ${RESOURCE_PATH}/ldif/vlv.ldif

# Add the base...
slapadd -F ${SLAPD_CONF} <<EOM
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
EOM

# Used to enable "ldaps://" (never standardized from an RFC like StartTLS, though still commonly used) ...
sed -i -e 's|^SLAPD_SERVICES="\(.*\)"|SLAPD_SERVICES="ldap:/// ldapi:/// ldaps:///"|' /etc/default/slapd

chown -R openldap.openldap ${SLAPD_CONF}
chown -R openldap.openldap ${SLAPD_DATA}

# Needed so we can access LDAP via the proper name in the cert, final one to test a failure...
grep 'ldap.example.com' /etc/hosts || echo "127.0.0.1 ldap.example.com" >> /etc/hosts
grep 'ldap.foo.com' /etc/hosts || echo "127.0.0.1 ldap.foo.com" >> /etc/hosts

service slapd start

# Import the test data ...
/usr/bin/time ldapadd -x -D "cn=admin,dc=example,dc=com" -w 12345 -h localhost -p 389 -f ${RESOURCE_PATH}/ldif/data.ldif > /dev/null
