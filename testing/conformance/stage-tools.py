#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage pinned public tools OUTSIDE the candidate; never run from a suite.

The output is a regular-file-only bundle and a controller input manifest. The
controller independently hashes every file before its read-only mount. Network
access is used only here, by the trusted provisioning phase. No package scripts,
Docker daemon, image execution or package manager is used.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import tarfile
import tempfile
import urllib.request

BUNDLE = "webrtc"
IMAGE = "https://mcr.microsoft.com/v2/playwright"
IMAGE_SHA = "bc72a8df40831ded821e3cbc79c318c21b44d6e51dff9fd89ace7a8249c5b462"
IMAGE_INDEX = "06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f"
MOUNT = "/opt/busbar-conformance/" + BUNDLE


def download(url, path, digest, headers=None, algorithm="sha256"):
    if not path.exists():
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=120) as source, path.open("wb") as target:
            shutil.copyfileobj(source, target)
    hasher = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    if hasher.hexdigest() != digest:
        raise ValueError("public input digest mismatch: " + url)
    return path


def selected(name):
    return name.startswith(("ms-playwright/chromium-1248/", "ms-playwright/firefox-1555/",
                            "usr/lib/x86_64-linux-gnu/", "usr/share/fonts/", "etc/alternatives/libblas",
                            "etc/alternatives/liblapack", "etc/alternatives/fonts-japanese-gothic.ttf"))


def unpack_layers(blobs, root):
    aliases = {}
    for blob in blobs:
        with tarfile.open(blob) as archive:
            for entry in archive:
                name = entry.name.removeprefix("./")
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("unsafe archive path")
                if not selected(name):
                    continue
                if path.name.startswith(".wh."):
                    # Apply OCI deletions before flattening the final public file tree.
                    victim = path.parent if path.name == ".wh..wh..opq" else path.parent / path.name[4:]
                    target = root / victim
                    if target.is_dir():
                        shutil.rmtree(target)
                    elif target.exists():
                        target.unlink()
                    prefix = str(victim) + "/"
                    aliases = {key: value for key, value in aliases.items()
                               if key != str(victim) and not key.startswith(prefix)}
                    continue
                if entry.isdir():
                    continue
                if entry.issym() or entry.islnk():
                    aliases[name] = (entry.linkname, entry.islnk())
                    continue
                if not entry.isfile():
                    raise ValueError("special file in public tool input")
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                target.chmod(0o755 if entry.mode & 0o111 else 0o644)
                aliases.pop(name, None)
    # Materialize symlink/hardlink aliases, never create symlinks or shared inodes.
    for _ in range(len(aliases) + 1):
        progress = False
        for name, (link, hard) in list(aliases.items()):
            source = root / link.lstrip("/") if link.startswith("/") or hard else (root / name).parent / link
            source = Path(os.path.normpath(source))
            if not source.is_relative_to(root):
                raise ValueError("archive alias escapes root")
            if source.is_file():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(source.stat().st_mode & 0o777)
                del aliases[name]
                progress = True
        if not progress:
            break
    # Unused Perl directory aliases are not part of the browser runtime.
    unresolved = [name for name in aliases if not name.startswith("usr/lib/x86_64-linux-gnu/perl/")]
    if unresolved:
        raise ValueError("unresolved tool aliases: " + repr(unresolved))


def relocate_interpreter(path, interpreter):
    """Append a PT_INTERP string, changing no ELF code or existing file offsets."""
    with path.open("rb") as stream:
        header = stream.read(64)
    if not header.startswith(b"\x7fELF"):
        return
    if header[4:6] != b"\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
        raise ValueError("expected a little-endian x86-64 ELF")
    offset = struct.unpack_from("<Q", header, 32)[0]
    size, count = struct.unpack_from("<HH", header, 54)
    if size != 56:
        raise ValueError("unexpected ELF program header size")
    with path.open("r+b") as stream:
        for index in range(count):
            position = offset + index * size
            stream.seek(position)
            ph = bytearray(stream.read(size))
            if struct.unpack_from("<I", ph)[0] != 3:
                continue
            stream.seek(0, os.SEEK_END)
            new_offset = stream.tell()
            value = interpreter.encode() + b"\0"
            stream.write(value)
            struct.pack_into("<Q", ph, 8, new_offset)
            struct.pack_into("<QQ", ph, 32, len(value), len(value))
            stream.seek(position)
            stream.write(ph)
            return


def npm_packages(repo, output, cache, provenance):
    lock = json.loads((repo / ("testing/" + BUNDLE + "-conformance/package-lock.json")).read_text())
    for name, record in lock["packages"].items():
        if not name:
            continue
        if not name.startswith("node_modules/") or ".." in PurePosixPath(name).parts:
            raise ValueError("invalid locked package path")
        algorithm, integrity = record["integrity"].split("-", 1)
        if algorithm != "sha512":
            raise ValueError("package lacks SHA512 integrity")
        digest = base64.b64decode(integrity, validate=True).hex()
        archive_path = download(record["resolved"], cache / (digest + ".tgz"), digest, algorithm=algorithm)
        provenance.append({"uri": record["resolved"], "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()})
        with tarfile.open(archive_path) as archive:
            for entry in archive:
                relative = PurePosixPath(entry.name)
                if relative.parts[0] != "package" or ".." in relative.parts:
                    raise ValueError("invalid npm archive path")
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ValueError("npm archive contains a nonregular file")
                target = output / name / Path(*relative.parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                target.chmod(0o755 if entry.mode & 0o111 else 0o644)


def assemble(root, output):
    (output / "bin").mkdir(parents=True)
    shutil.copytree(root / "ms-playwright", output / "browsers")
    shutil.copytree(root / "usr/lib/x86_64-linux-gnu", output / "lib")
    shutil.copytree(root / "usr/share/fonts", output / "fonts")
    (output / "fonts.conf").write_text(
        '<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">'
        f'<fontconfig><dir>{MOUNT}/fonts</dir><cachedir>/tmp/busbar-font-cache</cachedir></fontconfig>\n')
    for path in (output / "browsers").rglob("*"):
        if path.is_file():
            relocate_interpreter(path, MOUNT + "/lib/ld-linux-x86-64.so.2")
    for name, executable in {"chromium": "chromium-1248/chrome-linux64/chrome",
                             "firefox": "firefox-1555/firefox/firefox"}.items():
        (output / "bin" / name).write_text(
            "#!/bin/sh\nset -eu\n"
            f"export LD_LIBRARY_PATH={MOUNT}/lib\n"
            f"export FONTCONFIG_FILE={MOUNT}/fonts.conf\n"
            f"export FONTCONFIG_PATH={MOUNT}\n"
            f"exec {MOUNT}/browsers/{executable} \"$@\"\n")
        (output / "bin" / name).chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    args = parser.parse_args()
    output, cache = args.output.resolve(), args.cache.resolve()
    repo = Path(__file__).resolve().parents[2]
    if output.exists() or output.is_relative_to(repo) or cache.is_relative_to(repo):
        parser.error("output must be new; output and cache must be outside the candidate repository")
    cache.mkdir(parents=True, exist_ok=True)
    headers = {"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
    manifest_url = IMAGE + "/manifests/sha256:" + IMAGE_SHA
    manifest = json.loads(download(manifest_url, cache / (IMAGE_SHA + ".json"), IMAGE_SHA, headers).read_bytes())
    provenance = [{"uri": manifest_url, "sha256": IMAGE_SHA}]
    if IMAGE_INDEX != IMAGE_SHA:
        index_url = IMAGE + "/manifests/sha256:" + IMAGE_INDEX
        index = json.loads(download(index_url, cache / (IMAGE_INDEX + ".json"), IMAGE_INDEX, headers).read_bytes())
        if not any(row["digest"] == "sha256:" + IMAGE_SHA
                   and row["platform"] == {"architecture": "amd64", "os": "linux"}
                   for row in index["manifests"]):
            raise ValueError("pinned index does not name the expected linux/amd64 image")
        provenance.append({"uri": index_url, "sha256": IMAGE_INDEX})
    blobs = []
    for layer in manifest["layers"]:
        digest = layer["digest"].removeprefix("sha256:")
        url = IMAGE + "/blobs/sha256:" + digest
        blobs.append(download(url, cache / (digest + ".tar.gz"), digest, headers))
        provenance.append({"uri": url, "sha256": digest})
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stage-" + BUNDLE + "-", dir=output.parent) as temporary:
        root = Path(temporary)
        unpack_layers(blobs, root)
        assemble(root, output)
    npm_packages(repo, output, cache, provenance)
    files = {}
    for path in sorted(output.rglob("*")):
        if path.is_dir():
            path.chmod(0o755)
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("output contains a nonregular or multiply linked file")
        executable = bool(path.stat().st_mode & 0o111)
        path.chmod(0o755 if executable else 0o644)
        files[path.relative_to(output).as_posix()] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "executable": executable}
    manifest = {"schema": "busbar.native-conformance-inputs/1", "bundles": {
        BUNDLE: {"path": str(output), "files": files, "provenance": provenance}}}
    record = output.parent / (BUNDLE + "-inputs.json")
    record.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(record)


if __name__ == "__main__":
    main()
