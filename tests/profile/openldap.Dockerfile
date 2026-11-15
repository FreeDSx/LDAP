# check=skip=InvalidDefaultArgInFrom

ARG UBUNTU_VERSION

FROM ubuntu:${UBUNTU_VERSION} AS build

ARG OPENLDAP_VERSION
ARG OPENLDAP_SHA3_512

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        groff-base \
        libltdl-dev \
        libsasl2-dev \
        libssl-dev \
        openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Overlays are built as modules so any of them can be loaded through cn=config.
RUN curl -fsSL -o openldap.tgz \
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
    && { test "$(openssl dgst -sha3-512 -r openldap.tgz | cut -d ' ' -f 1)" = "${OPENLDAP_SHA3_512}" \
        || { echo "SHA3-512 mismatch for openldap-${OPENLDAP_VERSION}.tgz" >&2; exit 1; }; } \
    && tar xzf openldap.tgz --strip-components=1 \
    && ./configure --prefix=/usr/local --enable-modules --enable-overlays=mod \
    && make depend \
    && make -j"$(nproc)" \
    && make install

FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends libltdl7 libsasl2-2 libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local /usr/local

RUN ldconfig \
    && groupadd --system openldap \
    && useradd --system --gid openldap --home-dir /var/lib/ldap --shell /usr/sbin/nologin openldap \
    && mkdir -p /var/lib/ldap /etc/ldap/slapd.d \
    && chown openldap:openldap /var/lib/ldap /etc/ldap/slapd.d

COPY openldap-bootstrap.sh /openldap-bootstrap.sh
RUN chmod +x /openldap-bootstrap.sh

EXPOSE 389
ENTRYPOINT ["/openldap-bootstrap.sh"]
