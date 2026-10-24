# Current 389 Directory Server from Fedora packages, since the published images stopped at 2.4 for arm64.
FROM fedora:44

RUN dnf install -y --setopt=install_weak_deps=0 389-ds-base openldap-clients \
    && dnf clean all

# Fedora does not package the container entrypoint, so it comes from the source tag of the installed release.
RUN version="$(rpm -q --qf '%{VERSION}' 389-ds-base)" \
    && curl -fsSL -o /usr/libexec/dirsrv/dscontainer \
        "https://raw.githubusercontent.com/389ds/389-ds-base/389-ds-base-${version}/src/lib389/cli/dscontainer" \
    && chmod 755 /usr/libexec/dirsrv/dscontainer

RUN mkdir -p /data/config /data/ssca /data/run \
    && ln -sf /data/config /etc/dirsrv/slapd-localhost \
    && ln -sf /data/ssca /etc/dirsrv/ssca \
    && rm -rf /run/dirsrv \
    && ln -s /data/run /run/dirsrv \
    && chown -R dirsrv: /data /run/dirsrv \
    && chgrp -R dirsrv /etc/dirsrv

EXPOSE 3389 3636
CMD ["/usr/libexec/dirsrv/dscontainer", "-r"]
