#!/usr/bin/env bash

# Minimal vanilla slapd bootstrap for the bench profile container.

set -e

DATA="/var/lib/ldap"
RUN="/var/run/slapd"
CONF="/etc/ldap/slapd.conf"

mkdir -p "$RUN" "$DATA"
rm -rf "${DATA:?}"/*

ROOTPW=$(slappasswd -s 'P@ssword12345' -h '{SSHA}')

cat > "$CONF" <<EOF
include         /etc/ldap/schema/core.schema
include         /etc/ldap/schema/cosine.schema
include         /etc/ldap/schema/inetorgperson.schema
include         /etc/ldap/schema/nis.schema

pidfile         /var/run/slapd/slapd.pid
argsfile        /var/run/slapd/slapd.args

modulepath      /usr/lib/ldap
moduleload      back_mdb

loglevel        none

database        mdb
suffix          "dc=example,dc=com"
rootdn          "cn=admin,dc=example,dc=com"
rootpw          ${ROOTPW}

directory       /var/lib/ldap
maxsize         1073741824

index           objectClass             eq
index           cn,sn,uid,mail          eq,sub
index           ou                      eq

access to attrs=userPassword
        by self write
        by anonymous auth
        by * none
access to *
        by self write
        by * read
EOF

cat > /tmp/base.ldif <<'EOF'
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
EOF

slapadd -f "$CONF" -l /tmp/base.ldif

chown -R openldap:openldap "$DATA" "$RUN" "$CONF"

exec /usr/sbin/slapd \
    -d 0 \
    -u openldap \
    -g openldap \
    -f "$CONF" \
    -h "ldap:///"
