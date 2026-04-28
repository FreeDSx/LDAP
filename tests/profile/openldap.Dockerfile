FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY openldap-bootstrap.sh /openldap-bootstrap.sh
RUN chmod +x /openldap-bootstrap.sh

EXPOSE 389
ENTRYPOINT ["/openldap-bootstrap.sh"]
