#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
"""Verify the actual tar/deb payloads cannot install builder-owned writable files."""
import subprocess
import sys
import tarfile
import tempfile


def verify(archive):
    members = archive.getmembers()
    assert members, "empty archive"
    for member in members:
        assert member.uid == member.gid == 0, (member.name, "not root-owned")
        assert member.isdir() or member.isfile(), (member.name, "unexpected type")
        executable = member.name.endswith(("/bin/mqproxy", "/postinst", "/postrm"))
        expected = 0o755 if member.isdir() or executable else 0o644
        assert member.mode == expected, (member.name, oct(member.mode), oct(expected))


with tarfile.open(sys.argv[1]) as archive:
    verify(archive)
for option in ("--fsys-tarfile", "--ctrl-tarfile"):
    with tempfile.TemporaryFile() as payload:
        subprocess.run(["dpkg-deb", option, sys.argv[2]], stdout=payload, check=True)
        payload.seek(0)
        with tarfile.open(fileobj=payload) as archive:
            verify(archive)
print("PASS: tar/deb ownership and permissions")
