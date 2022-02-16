#!/usr/bin/env python3
"""Sync files from linux-firmware repository"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
from typing import Dict


BASE_PATH = Path(__file__).parent
LINUX_FIRMWARE_REPO = BASE_PATH / "linux-firmware"
LINUX_FIRMWARE_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git"
IWLWIFI_FIRMWARE_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/iwlwifi/linux-firmware.git"


# Fixup data because linux-firmware is not clean enough
FIXUP_VERSION_DATA = {
    # This is referenced as "v5.4.A.11 (aka v5.4.1.16)"
    ("caef650a8c909f557ed7f6b23c413401d6994fdb", "iwlwifi-5000-1.ucode"): "v5.4.1.16",
    # The WHENCE file was changed in the next commit, 5d1a03de9630e882f5c66eb3f516a206ce3c7714
    ("afe92a82d8825527bca60913de6bcf395329a060", "iwlwifi-105-6.ucode"): "v18.168.6.1",
    # The WHENCE file was changed in a later commit, 9be9ff282635c25694819c39aae0f6cc6c251c12
    ("a2c354e64cec4b1146054c7e5b7df4329af752a7", "iwlwifi-3168-21.ucode"): "21.302800.0",
    ("a2c354e64cec4b1146054c7e5b7df4329af752a7", "iwlwifi-7265D-21.ucode"): "21.302800.0",
    ("a2c354e64cec4b1146054c7e5b7df4329af752a7", "iwlwifi-8000C-21.ucode"): "21.302800.0",
    ("a2c354e64cec4b1146054c7e5b7df4329af752a7", "iwlwifi-8265-21.ucode"): "21.302800.0",
    # The file used an incorrect format and fixed in a later commit, 581f24500138f5e410d51ab63b205be9a52f4c77
    ("28ddb05aeeffcc08b2c18ea29793ff6e7f94b974", "intel/ibt-11-5.ddc"): "LnP/SfP_REL0351_incorrect",
    # The file used an incorrect format and fixed in a later commit, 581f24500138f5e410d51ab63b205be9a52f4c77
    ("87941021a622c882b1921df85d6115940a4e568a", "intel/ibt-12-16.ddc"): "BT_WindStormPeak_REL0082_incorrect",
}


def sync_linux_firmware(fw_repo: Path) -> None:
    if fw_repo.exists():
        print(f"Updating {fw_repo} ...", file=sys.stderr)
        subprocess.run(("git", "fetch", "origin"), cwd=fw_repo, check=True)
        subprocess.run(("git", "fetch", "iwlwifi"), cwd=fw_repo, check=True)
    else:
        print(f"Cloning {fw_repo} ...", file=sys.stderr)
        subprocess.run(
            ("git", "clone", str(LINUX_FIRMWARE_URL), LINUX_FIRMWARE_REPO.name),
            cwd=fw_repo.parent,
            check=True,
        )
        subprocess.run(
            ("git", "remote", "add", "-f", "iwlwifi", str(IWLWIFI_FIRMWARE_URL)),
            cwd=fw_repo,
            check=True,
        )

    print("Getting all commits", file=sys.stderr)
    all_file_hashes: Dict[str, bytes] = {}
    cmd_out = subprocess.check_output(
        ("git", "log", "--format=%H %as", "--all", "--reverse"),
        stdin=subprocess.DEVNULL,
        cwd=fw_repo,
    )
    for log_line in cmd_out.decode("ascii").splitlines():
        commit_hash, commit_date = log_line.split(" ")
        assert re.match(r"^[0-9a-f]{40}$", commit_hash), f"Invalid format for commit hash {commit_hash!r}"
        assert re.match(
            r"^[0-9]{4}-[01][0-9]-[0-3][0-9]$", commit_date
        ), f"Invalid format for commit date {commit_date!r}"
        commit_files_out = subprocess.check_output(
            ("git", "diff-tree", "--no-commit-id", "-r", commit_hash),
            stdin=subprocess.DEVNULL,
            cwd=fw_repo,
        )
        fw_file_hashes = {}
        for diff_line in commit_files_out.decode("ascii").splitlines():
            matches = re.match(r"^:[0-7]{6} ([0-7]{6}) [0-9a-f]{40} ([0-9a-f]{40}) [ADMT]\t(.*)$", diff_line)
            assert matches, f"Invalid git diff-tree {commit_hash} line: {diff_line!r}"
            file_mode, file_hash, file_name = matches.groups()
            if file_hash == "0000000000000000000000000000000000000000":
                continue
            if file_mode == "120000":
                # Ignore symbolic links
                continue
            # Only get WHENCE, Intel Wi-Fi and Intel Bluetooth firmware files
            if file_name == "WHENCE" or file_name.startswith(("iwl", "intel/ibt-")):
                assert file_mode in {
                    "100644",
                    "100755",
                }, f"Unexpected file mode {file_mode!r} for {file_name!r} in {commit_hash}"
                assert file_name not in fw_file_hashes, f"Duplicate {file_name!r} file found in {commit_hash}"
                fw_file_hashes[file_name] = file_hash

        # Ignore commits which do not introduce interesting files
        if all(name == "WHENCE" for name in fw_file_hashes.keys()):
            continue

        # Get a reference to the WHENCE file (which can be skipped in "git diff-tree" if it is not modified)
        whence_file_out = subprocess.check_output(
            ("git", "ls-tree", commit_hash, "WHENCE"),
            stdin=subprocess.DEVNULL,
            cwd=fw_repo,
        )
        lstree_line = whence_file_out.decode("ascii").strip()
        matches = re.match(r"^[0-7]{6} blob ([0-9a-f]{40})\tWHENCE$", lstree_line)
        assert matches, f"Invalid git ls-tree {commit_hash} line: {lstree_line!r}"
        whence_file_hash = matches.group(1)
        if "WHENCE" in fw_file_hashes:
            assert fw_file_hashes["WHENCE"] == whence_file_hash
            del fw_file_hashes["WHENCE"]

        # Parse the WHENCE file
        whence_file_bytes = subprocess.check_output(
            ("git", "cat-file", "blob", whence_file_hash),
            stdin=subprocess.DEVNULL,
            cwd=fw_repo,
        )
        whence_file = whence_file_bytes.decode("utf-8")

        # Read files
        if all_file_hashes:
            print("")
        print(f"{commit_date} {commit_hash} added {len(fw_file_hashes)} files")
        for file_name, file_hash in sorted(fw_file_hashes.items()):
            # Get the file content
            file_bytes = subprocess.check_output(
                ("git", "cat-file", "blob", file_hash),
                stdin=subprocess.DEVNULL,
                cwd=fw_repo,
            )
            # Skip empty files (git errors)
            if file_bytes == b"":
                continue

            version = None
            try:
                version = FIXUP_VERSION_DATA[(commit_hash, file_name)]
            except KeyError:
                offset = None
                for pattern in (
                    f"\nFile: {file_name}\nInfo: ",
                    f"\nFile: {file_name}\nVersion: ",
                    f"\nFile:{file_name}\nVersion: ",
                    f"\nFile: {file_name}\nVersion ",
                    f"\nFile {file_name}\nVersion ",
                ):
                    try:
                        offset = whence_file.index(pattern)
                    except ValueError:
                        continue
                    else:
                        break
                if offset is not None:
                    offset += len(pattern)
                    end_offset = whence_file.index("\n", offset)
                    version = whence_file[offset:end_offset]

            if version is not None:
                # Strip " (0x36)" at the end of some Bluetooth FW version
                matches = re.match(r"^(.*) \(0x[0-9A-Fa-f]+\)$", version)
                if matches:
                    version = matches.group(1)
                # Replace "LnP/SfP" with underscore
                if version.startswith("LnP/SfP_"):
                    version = "LnP_SfP_" + version[8:]
                # Strip leading "v"
                if re.match(r"^v([0-9.]+)$", version):
                    version = version[1:]

                date_and_version = f"{commit_date}__{version}"
            else:
                # print(f"\033[33mWarning: unable to find {file_name!r} in WHENCE at commit {commit_hash}\033[m")
                # Use the date by default
                version = commit_date
                date_and_version = commit_date

            if file_name.startswith("intel/ibt-"):
                local_file_name = f"{file_name[6:]}__{date_and_version}"
                local_dir_name = "intel_bluetooth"
            elif file_name.startswith("iwlwifi-"):
                local_file_name = f"{file_name}__{date_and_version}"
                local_dir_name = "intel_wifi"
            else:
                raise RuntimeError(f"Unable to categorize {file_name!r} in commit {commit_hash}")

            # Sanity check
            assert re.match(r"^[-0-9A-Za-z._]+$", date_and_version), f"Invalid format for version {date_and_version!r}"
            assert re.match(r"^[-0-9A-Za-z./]+$", file_name), f"Invalid format for file name {file_name!r}"
            assert re.match(r"^[-0-9A-Za-z._]+$", local_file_name), f"Invalid format for local name {local_file_name!r}"

            print(f"  - {file_name} version {version} ({len(file_bytes)} bytes)")

            file_bytes_digest = hashlib.sha256(file_bytes).digest()
            if local_file_name in all_file_hashes:
                if all_file_hashes[local_file_name] == file_bytes_digest:
                    # Skip a file with the same digest
                    continue
                # Add suffix while the file is not present
                already_seen_file_with_content = False
                while True:
                    local_file_name += "_"
                    if local_file_name not in all_file_hashes:
                        break
                    if all_file_hashes[local_file_name] == file_bytes_digest:
                        already_seen_file_with_content = True
                        break
                if already_seen_file_with_content:
                    continue
                print(f"    Warning: duplicate local file name, using {local_file_name}")
            all_file_hashes[local_file_name] = file_bytes_digest

            # Save the firmware file
            local_directory = BASE_PATH / local_dir_name
            local_directory.mkdir(exist_ok=True)
            with (local_directory / local_file_name).open("wb") as fout:
                fout.write(file_bytes)


if __name__ == "__main__":
    sync_linux_firmware(LINUX_FIRMWARE_REPO)
