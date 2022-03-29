#!/usr/bin/env python3
"""Compare the command codes with the one defined in iwlwifi, to find new ones

Source of information:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlwifi/fw/api
(old) https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/drivers/net/wireless/iwlwifi/mvm/fw-api.h
"""
import argparse
from pathlib import Path
import subprocess
import re
from typing import Dict

from parse_intel_wifi_fw import GROUP_CMD_ENUM, MvmCommandGroups


def compare_linux_command_codes(linux_path: Path, verbose: bool) -> None:
    # Establish a list of C enums to look for
    c_enums: Dict[str, int] = {}
    for cmd_group, enum_cls in GROUP_CMD_ENUM.items():
        if cmd_group == MvmCommandGroups.LONG:  # Skip LONG as it is the same as LEGACY
            assert MvmCommandGroups.LEGACY in GROUP_CMD_ENUM
            continue
        assert enum_cls.__doc__, f"Missing {enum_cls!r}.__doc__"
        matches = re.match("^enum ([a-z_]+)( .*)?$", enum_cls.__doc__)
        if not matches:
            raise ValueError(f"Unexpected help text in {enum_cls!r} class: {enum_cls.__doc__!r}")
        enum_name = matches.group(1)
        assert enum_name not in c_enums, f"Duplicated enum {enum_name!r} for {cmd_group} and {c_enums[enum_name]}"
        c_enums[enum_name] = cmd_group

    for subdir in ("drivers/net/wireless/intel/iwlwifi/fw/api/", "drivers/net/wireless/iwlwifi/mvm/"):
        cmd_out = subprocess.check_output(
            ("git", "log", "--format=%H %as", "--all", "--reverse", "--", subdir),
            stdin=subprocess.DEVNULL,
            cwd=linux_path,
        )
        for log_line in cmd_out.decode("ascii").splitlines():
            if verbose:
                print(f"Analyzing {log_line}")
            commit_hash, commit_date = log_line.split(" ")
            ls_tree_out = subprocess.check_output(
                ("git", "ls-tree", commit_hash, subdir),
                stdin=subprocess.DEVNULL,
                cwd=linux_path,
            )
            for lstree_line in ls_tree_out.decode("ascii").splitlines():
                matches = re.match(r"^[0-7]{6} blob ([0-9a-f]{40})\t(.*)$", lstree_line)
                assert matches, f"Invalid git ls-tree {commit_hash} line: {lstree_line!r}"
                file_hash, file_name = matches.groups()
                if verbose:
                    print(f"  {file_hash} {file_name}")

                file_bytes = subprocess.check_output(
                    ("git", "cat-file", "blob", file_hash),
                    stdin=subprocess.DEVNULL,
                    cwd=linux_path,
                )
                state = ""
                current_enum_cls = None
                for line in file_bytes.decode("utf-8").splitlines():
                    if state == "":
                        matches = re.match(r"^\s*enum\s+(\S+)", line)
                        if matches:
                            enum_name = matches.group(1)
                            try:
                                cmd_group = c_enums[enum_name]
                            except KeyError:
                                pass
                            else:
                                current_enum_cls = GROUP_CMD_ENUM[cmd_group]
                                if verbose:
                                    print(f"    {line} => class {current_enum_cls.__name__}")
                                state = "in_enum"
                        if line == "/* commands */":
                            # Old commands list:
                            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/iwlwifi/mvm/fw-api.h?id=175a70b7f22894cda03e1608f075c548656024f8#n88
                            current_enum_cls = GROUP_CMD_ENUM[MvmCommandGroups.LEGACY]
                            state = "in_enum"
                    elif state == "in_enum":  # Dirty parsing of a C header
                        assert current_enum_cls is not None
                        if line == "":
                            continue
                        if line == "enum {":
                            continue
                        if line == "};":
                            state = ""
                            current_enum_cls = None
                            continue
                        if line == "\t/**":
                            state = "in_enum/comment"
                            continue
                        if re.match(r"^\t/\* .*\*/$", line):
                            continue
                        if matches := re.match(r"^\t([0-9A-Z_]+) = ([0-9a-fA-Fx]+),(?: /\*.*\*/)?$", line):
                            if verbose:
                                print(f"    {line}")
                            name, value_s = matches.groups()
                            value = int(value_s, 0)

                            # NET_DETECT_... were renamed SCAN_OFFLOAD_...
                            if current_enum_cls == GROUP_CMD_ENUM[MvmCommandGroups.LEGACY]:
                                if name == "NET_DETECT_PROFILES_QUERY_CMD":
                                    name = "SCAN_OFFLOAD_PROFILES_QUERY_CMD"
                                elif name == "NET_DETECT_HOTSPOTS_CMD":
                                    name = "SCAN_OFFLOAD_HOTSPOTS_CONFIG_CMD"
                                elif name == "NET_DETECT_HOTSPOTS_QUERY_CMD":
                                    name = "SCAN_OFFLOAD_HOTSPOTS_QUERY_CMD"

                            if (
                                current_enum_cls == GROUP_CMD_ENUM[MvmCommandGroups.LEGACY]
                                and name == "SCAN_RESULTS_NOTIFICATION"
                            ):
                                # SCAN_RESULTS_NOTIFICATION was removed, then DC2DC_CONFIG_CMD was created with the same ID  # noqa
                                cur_item = current_enum_cls(0x83)
                            elif current_enum_cls == GROUP_CMD_ENUM[MvmCommandGroups.LEGACY] and name == "REPLY_MAX":
                                # Ignore old REPLY_MAX
                                if value != 0xFF:
                                    raise ValueError(
                                        f"Mismatched value: {current_enum_cls.__name__}.{name} = 0xff, not {value:#x}"
                                    )
                                continue
                            else:
                                try:
                                    cur_item = current_enum_cls.from_name(name)
                                except AttributeError:
                                    raise ValueError(
                                        f"Missing {current_enum_cls.__name__}.{name} = {value:#x} from {file_name} {commit_hash} line {line!r}"  # noqa
                                    )
                            if cur_item.value != value:
                                raise ValueError(
                                    f"Mismatched value: {current_enum_cls.__name__}.{name} = {cur_item.value:#x}, not {value:#x}"  # noqa
                                )
                            continue
                        raise NotImplementedError(f"[{state} {current_enum_cls}] line {line!r}")
                    elif state == "in_enum/comment":
                        if line.startswith("\t *") and "*/" not in line:
                            continue
                        if line == "\t */":
                            state = "in_enum"
                            continue
                        raise NotImplementedError(f"[{state} {current_enum_cls}] line {line!r}")
                    else:
                        raise NotImplementedError(f"[{state} {current_enum_cls}] line {line!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare the iwlwifi command codes with the known ones")
    parser.add_argument(
        "linux",
        type=Path,
        help="path to a clone of Linux kernel git repository",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Be verbose")
    args = parser.parse_args()
    compare_linux_command_codes(args.linux, args.verbose)
