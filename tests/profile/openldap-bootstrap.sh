#!/usr/bin/env bash

# Minimal vanilla slapd bootstrap for the bench profile container.

set -e

DATA="/var/lib/ldap"
RUN="/var/run/slapd"
CONF="/tmp/slapd.conf"
CONFIG_DIR="/etc/ldap/slapd.d"

mkdir -p "$RUN" "$DATA" "$CONFIG_DIR"

ROOTPW=$(slappasswd -s 'P@ssword12345' -h '{SSHA}')

cat > "$CONF" <<EOF
include         /usr/local/etc/openldap/schema/core.schema
include         /usr/local/etc/openldap/schema/cosine.schema
include         /usr/local/etc/openldap/schema/inetorgperson.schema
include         /usr/local/etc/openldap/schema/nis.schema

pidfile         /var/run/slapd/slapd.pid
argsfile        /var/run/slapd/slapd.args

modulepath      /usr/local/libexec/openldap
moduleload      memberof

loglevel        none

# The admin manages cn=config, where access rules can be changed at runtime.
database        config
access to *
        by dn.exact="cn=admin,dc=example,dc=com" manage
        by * none

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

# Only an empty data directory is seeded with the base entry, before the config conversion opens the database.
if [[ ! -f "$DATA/data.mdb" ]]; then
    slapadd -f "$CONF" -l /tmp/base.ldif
fi

# An existing config directory is kept along with any changes made through cn=config.
if [[ ! -f "$CONFIG_DIR/cn=config.ldif" ]]; then
    slaptest -f "$CONF" -F "$CONFIG_DIR"
fi

chown -R openldap:openldap "$DATA" "$RUN" "$CONFIG_DIR"

exec /usr/local/libexec/slapd \
    -d 0 \
    -u openldap \
    -g openldap \
    -F "$CONFIG_DIR" \
    -h "ldap:///"
