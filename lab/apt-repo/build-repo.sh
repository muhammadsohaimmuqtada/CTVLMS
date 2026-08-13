#!/usr/bin/env bash
set -euo pipefail
umask 022

pkg_root="/tmp/ctvlms-lab-pkg"
repo_root="/srv/repo"
rm -rf "$pkg_root" "$repo_root"
mkdir -p "$pkg_root/DEBIAN" "$pkg_root/usr/share/ctvlms-lab" "$repo_root"

cat > "$pkg_root/DEBIAN/control" <<'EOF'
Package: ctvlms-lab-pkg
Source: ctvlms-lab-pkg
Version: 1.1
Architecture: all
Maintainer: CTVLMS Pilot Lab <lab@invalid.example>
Section: admin
Priority: optional
Description: Deterministic CTVLMS remediation validation package
 This package exists only inside the isolated CTVLMS pilot lab.
EOF

printf '%s\n' '1.1' > "$pkg_root/usr/share/ctvlms-lab/version"
dpkg-deb --build "$pkg_root" "$repo_root/ctvlms-lab-pkg_1.1_all.deb" >/dev/null
cd "$repo_root"
dpkg-scanpackages . /dev/null > Packages
gzip -9 -c Packages > Packages.gz
