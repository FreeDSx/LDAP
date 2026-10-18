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
moduleload      memberof

loglevel        none

database        mdb
suffix          "dc=example,dc=com"
rootdn          "cn=admin,dc=example,dc=com"
rootpw          ${ROOTPW}

directory       /var/lib/ldap
maxsize         1073741824

# The bench administrator runs as free of limits as the rootdn and the FreeDSx side.
limits          group/groupOfNames/member="cn=bench-admins,dc=example,dc=com" size=unlimited time=unlimited

index           objectClass             eq
index           cn,sn,uid,mail          eq,sub
index           ou                      eq
index           member,memberOf         eq

# Maintains memberOf, which a membership comparison has no meaning without.
overlay              memberof
memberof-group-oc    groupOfNames
memberof-member-ad   member
memberof-memberof-ad memberOf
memberof-dangling    ignore
memberof-refint      TRUE

# The bench runs as a member of bench-admins rather than the rootdn and is held to these rules like the other sides.
access to attrs=userPassword
        by self write
        by anonymous auth
        by * none
access to *
        by group.exact="cn=bench-admins,dc=example,dc=com" write
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
