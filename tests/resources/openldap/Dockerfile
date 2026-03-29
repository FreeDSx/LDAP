FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    slapd \
    ldap-utils \
    gnutls-bin \
    ssl-cert \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY tests/resources/openldap/cert /etc/ldap/tls-templates
COPY tests/resources/openldap/ldif /etc/ldap/bootstrap-ldif
COPY tests/resources/openldap/docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh

EXPOSE 389 636

ENTRYPOINT ["/docker-entrypoint.sh"]
