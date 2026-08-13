FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    pkg=/tmp/ctvlms-lab-pkg; \
    mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/ctvlms-lab"; \
    printf '%s\n' \
      'Package: ctvlms-lab-pkg' \
      'Source: ctvlms-lab-pkg' \
      'Version: 1.0' \
      'Architecture: all' \
      'Maintainer: CTVLMS Pilot Lab <lab@invalid.example>' \
      'Section: admin' \
      'Priority: optional' \
      'Description: Deterministic CTVLMS remediation validation package' \
      ' This package exists only inside the isolated CTVLMS pilot lab.' \
      > "$pkg/DEBIAN/control"; \
    printf '%s\n' '1.0' > "$pkg/usr/share/ctvlms-lab/version"; \
    dpkg-deb --build "$pkg" /tmp/ctvlms-lab-pkg_1.0_all.deb >/dev/null; \
    dpkg -i /tmp/ctvlms-lab-pkg_1.0_all.deb; \
    rm -rf "$pkg" /tmp/ctvlms-lab-pkg_1.0_all.deb

RUN useradd --create-home --shell /bin/bash ctvlms-inventory \
    && useradd --create-home --shell /bin/bash ctvlms-patcher \
    && install -d -m 0755 /run/sshd \
    && printf '%s\n' \
       'PasswordAuthentication no' \
       'KbdInteractiveAuthentication no' \
       'PermitRootLogin no' \
       'PubkeyAuthentication yes' \
       'AllowUsers ctvlms-inventory ctvlms-patcher' \
       > /etc/ssh/sshd_config.d/ctvlms-lab.conf \
    && printf '%s\n' \
       'Cmnd_Alias CTVLMS_LAB_PATCH = /usr/bin/apt-get update, /usr/bin/apt-get install --only-upgrade -y ctvlms-lab-pkg' \
       'ctvlms-patcher ALL=(root) NOPASSWD: CTVLMS_LAB_PATCH' \
       > /etc/sudoers.d/ctvlms-lab \
    && chmod 0440 /etc/sudoers.d/ctvlms-lab

COPY entrypoint.sh /usr/local/bin/ctvlms-lab-entrypoint
RUN chmod 0755 /usr/local/bin/ctvlms-lab-entrypoint

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/ctvlms-lab-entrypoint"]
