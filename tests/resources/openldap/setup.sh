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

service slapd stop

# Remove existing data, reconfigure...
cp -v /var/lib/ldap/DB_CONFIG ./DB_CONFIG
rm -rf /etc/ldap/slapd.d/*
rm -rf /var/lib/ldap/*
cp -v ./DB_CONFIG /var/lib/ldap/DB_CONFIG

# Some initial imports...
slapadd -F /etc/ldap/slapd.d -b "cn=config" -l ./tests/resources/openldap/conf.ldif
slapadd -F /etc/ldap/slapd.d -b "cn=config" -l ./tests/resources/openldap/memberof.ldif

# Add the base...
slapadd -F /etc/ldap/slapd.d <<EOM
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
EOM

chown -R openldap.openldap /etc/ldap/slapd.d
chown -R openldap.openldap /var/lib/ldap

service slapd start

# Import the test data ...
/usr/bin/time ldapadd -x -D "cn=admin,dc=example,dc=com" -w 12345 -h localhost -p 389 -f ./tests/resources/openldap/data.ldif

# The CA cert is auto-generated and committed via a separate script
cp "./tests/resources/cert/data/cert.pem" "/usr/local/share/ca-certificates/example.crt"
cp "./tests/resources/cert/data/key.pem" "/etc/ssl/private/example.key"

update-ca-certificates

certtool --generate-privkey \
  --bits 2048 \
  --outfile /etc/ssl/private/slapd.key

sh -c "cat > /etc/ssl/slapd.info <<EOF
organization = Example
cn = ldap.example.com
dns_name = ldap.example.com
dns_name = example.com
dns_name = localhost
tls_www_server
encryption_key
signing_key
expiration_days = 1095
EOF"

# Generate the actual cert used by slapd and modify the config to use it
certtool --generate-certificate \
  --load-privkey /etc/ssl/private/slapd.key \
  --load-ca-certificate "/usr/local/share/ca-certificates/example.crt" \
  --load-ca-privkey "/etc/ssl/private/example.key" \
  --template /etc/ssl/slapd.info \
  --outfile /etc/ssl/certs/slapd.crt

ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF | true
dn: cn=config
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /usr/local/share/ca-certificates/example.crt
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ssl/certs/slapd.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ssl/private/slapd.key
EOF

# Used to enable "ldaps://" (never standardized from an RFC like StartTLS, though still commonly used) ...
sed -i -e 's|^SLAPD_SERVICES="\(.*\)"|SLAPD_SERVICES="ldap:/// ldapi:/// ldaps:///"|' /etc/default/slapd

# Needed permission / user changes ...
adduser openldap ssl-cert
chgrp ssl-cert /etc/ssl/private/slapd.key
chmod g+r /etc/ssl/private/slapd.key
chmod o-r /etc/ssl/private/slapd.key

# Needed so we can access LDAP via the proper name in the cert...
echo "127.0.0.1 ldap.example.com" >> /etc/hosts
echo "127.0.0.1 example.com" >> /etc/hosts

service slapd restart
