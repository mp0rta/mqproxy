#!/usr/bin/env python3
"""Build native Rust .deb and tar artifacts; run on each target architecture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def output(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def build():
    os.chdir(ROOT)
    os.umask(0o022)  # Package permissions must not inherit the builder's umask.
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "mqproxy"], check=True)
    metadata = json.loads(output("cargo", "metadata", "--locked", "--format-version", "1"))
    package = next(p for p in metadata["packages"] if p["name"] == "mqproxy")
    version = package["version"]
    arch = output("dpkg", "--print-architecture")
    if arch not in ("amd64", "arm64"):
        raise SystemExit(f"unsupported release architecture: {arch}")
    binary = Path(metadata["target_directory"]) / "release/mqproxy"
    machine = output("readelf", "-h", str(binary))
    assert ("X86-64" if arch == "amd64" else "AArch64") in machine, "binary architecture mismatch"
    dist = ROOT / "target/dist"
    dist.mkdir(parents=True, exist_ok=True)
    # Keep each build isolated, including dpkg-shlibdeps' source control file.
    with tempfile.TemporaryDirectory(prefix="mqproxy-package-") as tmp:
        work = Path(tmp)
        stage = work / "stage"
        doc = stage / "usr/share/doc/mqproxy"

        def install(src, dst, mode=0o644):
            dst = stage / dst
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            dst.chmod(mode)

        install(binary, "usr/bin/mqproxy", 0o755)
        subprocess.run(["strip", str(stage / "usr/bin/mqproxy")], check=True)
        for unit in (ROOT / "packaging/systemd").glob("*.in"):
            install(unit, f"usr/lib/systemd/system/{unit.stem}")
        for kind in ("sysusers.d", "tmpfiles.d"):
            install(ROOT / f"packaging/{kind}/mqproxy.conf", f"usr/lib/{kind}/mqproxy.conf")
        for name in ("LICENSE", "NOTICE", "server.conf.example", "client.conf.example"):
            install(ROOT / name, f"usr/share/doc/mqproxy/{name}")
        for name, source in (("xquic", "third_party/xquic/LICENSE"),
                             ("boringssl", "third_party/xquic/third_party/boringssl/LICENSE")):
            install(ROOT / source, f"usr/share/doc/mqproxy/third-party/{name}.txt")
        # Include the locked production/build dependency notices, not a hand-maintained list.
        tree = output("cargo", "tree", "--locked", "-p", "mqproxy", "--edges", "normal,build",
                      "--prefix", "none", "--format", "{p}")
        used = {tuple(line.split()[:2]) for line in tree.splitlines()}
        inventory = []
        for p in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
            if not p["source"] or (p["name"], "v" + p["version"]) not in used:
                continue
            source = Path(p["manifest_path"]).parent
            notices = [f for f in source.iterdir() if f.is_file()
                       and f.name.lower().startswith(("license", "licence", "copying", "notice", "copyright"))]
            if p["license_file"]:
                notices.append(source / p["license_file"])
            # asn1-rs-impl 0.2.0 omits its workspace license files from the archive.
            # It is Apache-2.0 OR MIT; distribute under Apache-2.0 with its metadata.
            if p["name"] == "asn1-rs-impl" and p["version"] == "0.2.0" and not notices:
                install(ROOT / "LICENSE", f"usr/share/doc/mqproxy/third-party/asn1-rs-impl-0.2.0/LICENSE-APACHE")
                notices = [source / "Cargo.toml"]
            if not notices:
                raise RuntimeError(f"missing license text for {p['name']} {p['version']}")
            for f in set(notices):
                install(f, f"usr/share/doc/mqproxy/third-party/{p['name']}-{p['version']}/{f.name}")
            inventory.append(f"{p['name']} {p['version']}: {p['license'] or p['license_file']}")
        (doc / "third-party/RUST-DEPENDENCIES.txt").write_text("\n".join(inventory) + "\n")
        subprocess.run(["bash", str(ROOT / "tests/packaging/verify_install.sh"), str(stage)], check=True)
        # tar carries the same installed tree, without Debian control metadata.
        tar = dist / f"mqproxy_{version}_{arch}.tar.gz"
        def root_owner(info):
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            return info

        with tarfile.open(tar, "w:gz") as archive:
            archive.add(stage / "usr", arcname="usr", filter=root_owner)
        (work / "debian").mkdir()
        (work / "debian/control").write_text("Source: mqproxy\nSection: net\nPriority: optional\nMaintainer: mp0rta\n\nPackage: mqproxy\nArchitecture: any\nDescription: Multipath QUIC application proxy\n")
        deps = output("dpkg-shlibdeps", "-O", "-e" + str(stage / "usr/bin/mqproxy"), cwd=work)
        deps = next(line.removeprefix("shlibs:Depends=") for line in deps.splitlines()
                    if line.startswith("shlibs:Depends="))
        control = stage / "DEBIAN"
        control.mkdir()
        size = sum(f.stat().st_size for f in (stage / "usr").rglob("*") if f.is_file())
        (control / "control").write_text(
            f"Package: mqproxy\nVersion: {version}\nArchitecture: {arch}\n"
            f"Maintainer: mp0rta\nSection: net\nPriority: optional\nDepends: {deps}\n"
            f"Installed-Size: {(size + 1023) // 1024}\nHomepage: https://github.com/mp0rta/mqproxy\n"
            "Description: Multipath QUIC application proxy/accelerator\n")
        for script in ("postinst", "postrm"):
            install(ROOT / f"packaging/{script}", f"DEBIAN/{script}", 0o755)
        deb = dist / f"mqproxy_{version}_{arch}.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(deb)], check=True)
        subprocess.run(["python3", str(ROOT / "tests/packaging/verify_archives.py"),
                        str(tar), str(deb)], check=True)
        print(f"Built {deb}\nBuilt {tar}")


if __name__ == "__main__":
    build()
