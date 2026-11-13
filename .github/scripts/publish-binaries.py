#!/usr/bin/env python3
"""Publish three validated binary assets; never access the application source repo."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "Kernefix/DiscordLink-Releases"
BLOBS = {"README.md", "CHANGELOG.md", "THIRD-PARTY-NOTICES.md", "LICENSE", ".gitignore",
         ".github/workflows/publish-binaries.yml", ".github/scripts/publish-binaries.py"}
TREES = {".github", ".github/workflows", ".github/scripts"}
MAX_ASSET = 1024 * 1024 * 1024


class Refused(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def gh(*arguments, optional=False):
    environment = dict(os.environ)
    environment.pop("GH_DEBUG", None)
    environment["GH_PROMPT_DISABLED"] = "1"
    result = subprocess.run(["gh", *arguments], capture_output=True, text=True,
                            env=environment, timeout=300)
    if result.returncode:
        if optional and "(HTTP 404)" in result.stderr:
            return None
        # gh diagnostics can include URLs. Keep event URLs and credentials out
        # of public logs, including on authentication or download failures.
        raise Refused("GitHub operation failed; no release files were replaced")
    return result.stdout


def api(endpoint, optional=False):
    result = gh("api", endpoint, optional=optional)
    return None if result is None else json.loads(result)


def validate_payload(event):
    require(event.get("action") == "validated-release", "Unexpected dispatch type")
    value = event.get("client_payload")
    require(isinstance(value, dict) and type(value.get("schema")) is int and value["schema"] == 1,
            "Unsupported publication request")
    require(isinstance(value.get("request_id"), str) and
            re.fullmatch(r"[a-f0-9]{32}", value["request_id"]), "Invalid request identifier")
    tag = value.get("tag")
    require(isinstance(tag, str) and re.fullmatch(r"v\d+[.]\d+[.]\d+(?:[.]\d+)?", tag),
            "Invalid release tag")
    title, notes = value.get("title"), value.get("notes")
    require(isinstance(title, str) and 0 < len(title) <= 256 and
            not any(ord(char) < 32 for char in title), "Invalid release title")
    require(isinstance(notes, str) and len(notes.encode("utf-8")) <= 65536 and
            "```" not in notes and "~~~" not in notes, "Release notes are not approved prose")
    require(type(value.get("prerelease")) is bool, "Invalid release stage")
    names = {f"DiscordLink_{tag[1:]}_Setup.exe", f"DiscordLink_{tag[1:]}.zip", "update-manifest.json"}
    assets = value.get("assets")
    require(isinstance(assets, list) and len(assets) == 3, "Exactly three assets are required")
    result = {}
    for item in assets:
        require(isinstance(item, dict) and item.get("name") in names and item["name"] not in result,
                "Unexpected or duplicate binary asset")
        require(type(item.get("size")) is int and 0 < item["size"] <= MAX_ASSET,
                "Invalid binary asset size")
        require(isinstance(item.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]),
                "Invalid binary asset digest")
        url = item.get("url")
        require(isinstance(url, str) and len(url) <= 16384 and
                not any(ord(char) < 32 for char in url), "Invalid asset download URL")
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname == "release-assets.githubusercontent.com" and
                parsed.port in (None, 443) and not parsed.username and not parsed.password and
                not parsed.fragment and parsed.path.startswith("/github-production-release-asset/"),
                "Asset download host is not approved")
        result[item["name"]] = item
    require(set(result) == names, "Binary asset set is incomplete")
    return value, result


def verify_public_commit(commit):
    require(isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}", commit), "Invalid public commit")
    metadata = api(f"repos/{REPOSITORY}/git/commits/{commit}")
    tree_sha = metadata.get("tree", {}).get("sha")
    require(isinstance(tree_sha, str) and re.fullmatch(r"[a-f0-9]{40}", tree_sha), "Public tree is invalid")
    tree = api(f"repos/{REPOSITORY}/git/trees/{tree_sha}?recursive=1")
    require(tree.get("truncated") is False and isinstance(tree.get("tree"), list) and tree["tree"],
            "Public tree cannot be verified")
    require(all((entry.get("type") == "blob" and entry.get("path") in BLOBS) or
                (entry.get("type") == "tree" and entry.get("path") in TREES) for entry in tree["tree"]),
            "Public tree contains files outside documentation and publication automation")


def tag_commit(tag):
    ref = api(f"repos/{REPOSITORY}/git/ref/tags/{tag}", optional=True)
    if ref is None:
        return None
    obj = ref.get("object", {})
    for _ in range(4):
        require(isinstance(obj.get("sha"), str) and re.fullmatch(r"[a-f0-9]{40}", obj["sha"]),
                "Invalid public tag object")
        if obj.get("type") == "commit":
            return obj["sha"]
        require(obj.get("type") == "tag", "Public tag does not identify a commit")
        obj = api(f"repos/{REPOSITORY}/git/tags/{obj['sha']}").get("object", {})
    raise Refused("Public tag nesting is excessive")


def release_for_tag(tag):
    release = api(f"repos/{REPOSITORY}/releases/tags/{tag}", optional=True)
    if release is not None:
        return release
    # The tag endpoint intentionally omits drafts, even for their owner.
    releases = api(f"repos/{REPOSITORY}/releases?per_page=100")
    require(isinstance(releases, list) and len(releases) < 100, "Release list is incomplete")
    found = [release for release in releases if release.get("tag_name") == tag]
    require(len(found) <= 1, "Duplicate release drafts require manual inspection")
    return found[0] if found else None


def verify_remote(release, assets, complete):
    found = {}
    for asset in release.get("assets", []):
        name = asset.get("name")
        remote_digest = asset.get("digest")
        require(name in assets and name not in found and asset.get("state") == "uploaded" and
                asset.get("size") == assets[name]["size"] and isinstance(remote_digest, str) and
                remote_digest.lower() == "sha256:" + assets[name]["sha256"],
                "Existing public asset differs; published files are never overwritten")
        found[name] = asset
    require(not complete or set(found) == set(assets), "Public upload is incomplete")
    return found


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def download(asset, destination):
    # A short-lived URL authorizes only this intended public binary. Never send
    # the repository token to a download host, or follow arbitrary redirects.
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "DiscordLink-Publication"})
    deadline = time.monotonic() + 120
    hashed, count = hashlib.sha256(), 0
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response, destination.open("xb") as output:
            require(response.status == 200, "Binary download did not succeed")
            length = response.headers.get("Content-Length")
            require(length is None or int(length) == asset["size"], "Download length differs")
            while True:
                require(time.monotonic() < deadline, "Binary download exceeded its time limit")
                data = response.read1(1024 * 1024)
                if not data:
                    break
                count += len(data)
                require(count <= asset["size"], "Downloaded binary exceeds its approved size")
                hashed.update(data)
                output.write(data)
    except (urllib.error.URLError, OSError, ValueError):
        raise Refused("Binary download failed or its temporary URL expired") from None
    require(count == asset["size"] and hashed.hexdigest() == asset["sha256"], "Downloaded binary digest differs")


def verify_package(directory, tag, assets):
    version = tag[1:]
    setup = f"DiscordLink_{version}_Setup.exe"
    manifest_file = directory / "update-manifest.json"
    require(manifest_file.stat().st_size <= 65536, "Update manifest is oversized")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8-sig"))
    require(manifest.get("schema") == 1 and manifest.get("version") == version and manifest.get("file") == setup and
            str(manifest.get("sha256", "")).lower() == assets[setup]["sha256"] and
            type(manifest.get("bytes")) is int and manifest["bytes"] == assets[setup]["size"],
            "Manifest does not describe the exact approved Setup")
    forbidden = {".cs", ".csproj", ".sln", ".pdb", ".xaml", ".vb", ".fs", ".cpp", ".h", ".py", ".ps1", ".bat", ".cmd"}
    with zipfile.ZipFile(directory / f"DiscordLink_{version}.zip") as archive:
        entries, names = archive.infolist(), set()
        require(len(entries) <= 1024 and sum(item.file_size for item in entries) <= 2 * MAX_ASSET, "ZIP exceeds package limits")
        for item in entries:
            normalized = item.filename.replace("\\", "/")
            path = PurePosixPath(normalized)
            require(normalized and not path.is_absolute() and ".." not in path.parts and
                    not any(":" in part for part in path.parts) and not any(ord(c) < 32 for c in normalized), "ZIP has an unsafe path")
            require(path.suffix.casefold() not in forbidden and ".git" not in (part.casefold() for part in path.parts) and
                    stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK, "ZIP contains source, debug symbols or links")
            if not item.is_dir():
                require(str(path).casefold() not in names, "ZIP contains duplicate paths")
                names.add(str(path).casefold())
        require({"discordlink.exe", "engine/manifest.json"} <= names, "ZIP lacks application or engine metadata")


def create_draft(value, head, directory):
    # Use the creation response's numeric ID. A just-created draft may not be
    # immediately visible through the cached release list or published-tag API.
    request_file = directory / "draft-request.json"
    request_file.write_text(json.dumps({
        "tag_name": value["tag"], "target_commitish": head,
        "name": value["title"], "body": value["notes"],
        "draft": True, "prerelease": value["prerelease"],
    }), encoding="utf-8")
    created = json.loads(gh("api", "--method", "POST", f"repos/{REPOSITORY}/releases",
                            "--input", str(request_file)))
    require(type(created.get("id")) is int and created.get("draft") is True and
            created.get("tag_name") == value["tag"], "GitHub did not return the exact created draft")
    return created


def publish(value, assets):
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "Publication is restricted to the public download repo")
    repository = api(f"repos/{REPOSITORY}")
    require(repository.get("private") is False and repository.get("full_name") == REPOSITORY and
            not repository.get("fork"), "Download repository must be public and separate")
    head = os.environ.get("GITHUB_SHA", "")
    verify_public_commit(head)
    tag = value["tag"]
    existing_tag = tag_commit(tag)
    if existing_tag:
        verify_public_commit(existing_tag)
    release = release_for_tag(tag)
    if release:
        require(existing_tag is not None or release.get("draft") is True and
                release.get("target_commitish") in (head, repository.get("default_branch")), "Unverified release tag")
        verify_remote(release, assets, complete=release.get("draft") is False)
        if release.get("draft") is False:
            require(release.get("prerelease") == value["prerelease"], "Published release stage differs")
            return release["html_url"]
    with tempfile.TemporaryDirectory(prefix="DiscordLink-public-binaries-") as temporary:
        directory = Path(temporary)
        for name, asset in assets.items():
            download(asset, directory / name)
        verify_package(directory, tag, assets)
        if existing_tag is None:
            gh("api", "--method", "POST", f"repos/{REPOSITORY}/git/refs",
               "-f", "ref=refs/tags/" + tag, "-f", "sha=" + head)
            require(tag_commit(tag) == head, "Public tag creation did not retain its verified target")
        notes = directory / "release-notes.md"
        notes.write_text(value["notes"], encoding="utf-8")
        if release is None:
            release = create_draft(value, head, directory)
        require(release is not None and type(release.get("id")) is int, "Public draft was not created")
        release_id = release["id"]
        release = api(f"repos/{REPOSITORY}/releases/{release_id}")
        if release.get("draft") is False:
            verify_remote(release, assets, complete=True)
            require(release.get("prerelease") == value["prerelease"], "Published release stage differs")
            return release["html_url"]
        require(release.get("draft") is True, "Public draft state is unknown")
        present = verify_remote(release, assets, complete=False)
        for name in sorted(set(assets) - set(present)):
            gh("release", "upload", tag, str(directory / name), "--repo", REPOSITORY)
        for attempt in range(5):
            release = api(f"repos/{REPOSITORY}/releases/{release_id}")
            try:
                verify_remote(release, assets, complete=True)
                break
            except Refused:
                if attempt == 4:
                    raise
                time.sleep(1)
        require(api(f"repos/{REPOSITORY}").get("private") is False, "Repository visibility changed")
        verify_public_commit(tag_commit(tag))
        gh("release", "edit", tag, "--repo", REPOSITORY, "--title", value["title"], "--notes-file", str(notes),
           "--draft=false", "--prerelease=" + str(value["prerelease"]).lower())
        final = api(f"repos/{REPOSITORY}/releases/{release_id}")
        require(final.get("draft") is False and final.get("prerelease") == value["prerelease"], "Public release stage differs")
        verify_remote(final, assets, complete=True)
        return final["html_url"]


def main():
    try:
        event_file = Path(os.environ["GITHUB_EVENT_PATH"])
        require(event_file.stat().st_size <= 256 * 1024, "Publication event is oversized")
        value, assets = validate_payload(json.loads(event_file.read_text(encoding="utf-8")))
        print(publish(value, assets))
    except (Refused, OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        # Do not print raw network/subprocess exceptions: they may contain a URL.
        message = str(error) if isinstance(error, Refused) else "Publication could not complete; details are withheld to protect temporary URLs"
        raise SystemExit("Public publication failed: " + message) from None


if __name__ == "__main__":
    main()
