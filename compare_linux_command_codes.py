#!/usr/bin/env python3
"""Compare the command codes with the one defined in iwlwifi, to find new ones

Source of information:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlwifi/fw/api
(old) https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/drivers/net/wireless/iwlwifi/mvm/fw-api.h
"""
import argparse
import enum
from pathlib import Path
import subprocess
import re
from typing import Dict, Type

import parse_intel_wifi_fw
from parse_intel_wifi_fw import GROUP_CMD_ENUM, MvmCommandGroups


def compare_linux_command_codes(linux_path: Path, verbose: bool) -> None:
    # Establish a list of C enums to look for
    c_enums: Dict[str, Type[enum.IntEnum]] = {}
    prefix_for_c_enum: Dict[str, str] = {}
    suffix_for_c_enum: Dict[str, str] = {}
    macro_prefix_as_enum: Dict[str, Type[enum.IntEnum]] = {}
    for cmd_group, enum_cls in GROUP_CMD_ENUM.items():
        if cmd_group == MvmCommandGroups.LONG:  # Skip LONG as it is the same as LEGACY
            assert MvmCommandGroups.LEGACY in GROUP_CMD_ENUM
            continue
        assert enum_cls.__doc__, f"Missing {enum_cls!r}.__doc__"
        matches = re.match("^enum ([a-z_]+)( .*)?$", enum_cls.__doc__)
        if not matches:
            raise ValueError(f"Unexpected help text in {enum_cls!r} class: {enum_cls.__doc__!r}")
        enum_name = matches.group(1)
        assert (
            enum_name not in c_enums
        ), f"Duplicated enum {enum_name!r} for {cmd_group} ({enum_cls!r}) and {c_enums[enum_name]!r}"
        c_enums[enum_name] = enum_cls

    # Grab all enums defined in parse_intel_wifi_fw
    for attr_name in dir(parse_intel_wifi_fw):
        enum_cls = getattr(parse_intel_wifi_fw, attr_name)
        try:
            if not issubclass(enum_cls, enum.IntEnum):
                continue
        except TypeError:
            continue
        assert enum_cls.__doc__, f"Missing {enum_cls!r}.__doc__"
        doc_first_line = enum_cls.__doc__.splitlines()[0]
        if matches := re.match(r"^(old )?enum ([a-z_]+) \(prefix ([A-Z_]+)\)$", doc_first_line):
            is_old, enum_name, enum_prefix = matches.groups()
            if is_old:
                enum_name = "old:" + enum_name
            assert (
                enum_name not in c_enums
            ), f"Duplicated enum {enum_name!r} for {enum_cls!r} and {c_enums[enum_name]!r}"
            assert enum_name not in prefix_for_c_enum
            c_enums[enum_name] = enum_cls
            prefix_for_c_enum[enum_name] = enum_prefix
            continue

        if matches := re.match(r"^enum ([a-z_]+) \(suffix ([A-Z_]+)\)$", doc_first_line):
            enum_name, enum_suffix = matches.groups()
            assert (
                enum_name not in c_enums
            ), f"Duplicated enum {enum_name!r} for {enum_cls!r} and {c_enums[enum_name]!r}"
            assert enum_name not in suffix_for_c_enum
            c_enums[enum_name] = enum_cls
            suffix_for_c_enum[enum_name] = enum_suffix
            continue

        if matches := re.match(r"^enum ([a-z_]+)(?: \([^)]+\))?$", doc_first_line):
            enum_name = matches.group(1)
            if c_enums.get(enum_name) == enum_cls:
                # Skip enums which were already included
                continue
            assert (
                enum_name not in c_enums
            ), f"Duplicated enum {enum_name!r} for {enum_cls!r} and {c_enums[enum_name]!r}"
            c_enums[enum_name] = enum_cls
            continue

        if matches := re.match(r"^Macros with prefix ([A-Z_]+)$", doc_first_line):
            macro_prefix = matches.group(1)
            assert (
                macro_prefix not in macro_prefix_as_enum
            ), f"Duplicated macro prefix {macro_prefix!r} for {enum_cls!r} and {macro_prefix_as_enum[enum_name]!r}"
            macro_prefix_as_enum[macro_prefix] = enum_cls
            continue
        raise ValueError(f"Unexpected help text in {enum_cls!r} class: {doc_first_line!r}")

    # for subdir in ("drivers/net/wireless/intel/iwlwifi/fw/api/", "drivers/net/wireless/iwlwifi/mvm/"):
    for subdir in ("drivers/net/wireless/intel/iwlwifi/", "drivers/net/wireless/iwlwifi/"):
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
                ("git", "ls-tree", "-r", commit_hash, subdir),
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
                current_enum_prefix = None
                current_enum_suffix = None
                current_enum_last_value = None
                for line in file_bytes.decode("utf-8").splitlines():
                    # print(repr(state), repr(line))
                    if state == "":
                        if matches := re.match(r"^\s*enum\s+(\S+)", line):
                            # Skip false-positives
                            if line.strip() == "enum {":
                                continue
                            if re.match(r"^\s*enum {\s*/\* [^*]+ \*/$", line):
                                continue
                            if re.match(r"^\s*enum ([0-9A-Za-z_]+) \*?([0-9A-Za-z_]+)[,)]", line):
                                # The line is a function parameter, ignore it.
                                continue
                            if re.match(r"^\s*enum ([0-9A-Za-z_]+)[,)]", line):
                                # The line is an anonymous function parameter, ignore it.
                                continue
                            if re.match(r"^\s*enum ([0-9A-Za-z_]+) \*?([0-9A-Za-z_\[\]]+);", line):
                                # The line is a global declaration, ignore it.
                                continue
                            if re.match(r"^\s*enum ([0-9A-Za-z_]+) \*?([0-9A-Za-z_]+) =", line):
                                # The line is a variable assignment, ignore it.
                                continue
                            if re.match(r"^\s*enum ([0-9A-Za-z_]+) ([0-9A-Za-z_]+)\(", line):
                                # The line is a function declaration, ignore it.
                                continue
                            # Be more restrictive on the pattern matching
                            matches = re.match(r"^\s*enum +([0-9A-Za-z_]+) {$", line)
                            if not matches:
                                raise NotImplementedError(f"Unknown enum line pattern {line!r}")
                            (enum_name,) = matches.groups()
                            try:
                                current_enum_cls = c_enums[enum_name]
                            except KeyError:
                                pass
                            else:
                                current_enum_prefix = prefix_for_c_enum.get(enum_name)
                                current_enum_suffix = suffix_for_c_enum.get(enum_name)
                                current_enum_last_value = -1
                                if verbose:
                                    print(f"    {line} => class {current_enum_cls.__name__}")
                                state = "in_enum"
                                continue
                        if line == "/* commands */":
                            # Old commands list:
                            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/iwlwifi/mvm/fw-api.h?id=175a70b7f22894cda03e1608f075c548656024f8#n88
                            state = "after_commands_comment"
                            continue
                        if matches := re.match(r"^\s*#\s*define\s+(\S+)\s+(.*)$", line):
                            # Parse macro
                            macro_name, macro_value = matches.groups()
                            for macro_prefix, enum_cls in macro_prefix_as_enum.items():
                                if macro_name.startswith(macro_prefix):
                                    if verbose:
                                        print(f"    {line} => class {enum_cls.__name__}")
                                    name = macro_name[len(macro_prefix):]
                                    value = int(macro_value, 0)
                                    try:
                                        cur_item = (
                                            enum_cls.from_name(name)
                                            if hasattr(enum_cls, "from_name")
                                            else getattr(enum_cls, name)
                                        )
                                    except AttributeError:
                                        raise ValueError(
                                            f"Missing {enum_cls.__name__}.{name} = {value:#x} from {file_name} {commit_hash} line {line!r}"  # noqa
                                        )
                                    if cur_item.value != value:
                                        raise ValueError(
                                            f"Mismatched value: {enum_cls.__name__}.{name} = {cur_item.value:#x}, not {value:#x}"  # noqa
                                        )

                    elif state == "after_commands_comment":
                        if line == "enum {":
                            # Confirm the enum
                            current_enum_cls = GROUP_CMD_ENUM[MvmCommandGroups.LEGACY]
                            current_enum_prefix = None
                            current_enum_suffix = None
                            current_enum_last_value = -1
                            state = "in_enum"
                            continue
                        # Otherwise, fall back to the initial state
                        state = ""
                    elif state == "in_enum":  # Dirty parsing of a C header
                        assert current_enum_cls is not None
                        if line == "":
                            continue
                        if line == "};" or re.match(r"^}; /\* .*\*/$", line):
                            state = ""
                            current_enum_cls = None
                            current_enum_prefix = None
                            current_enum_suffix = None
                            current_enum_last_value = None
                            continue
                        if line in {"\t/**", "\t/*"}:
                            state = "in_enum/comment"
                            continue
                        if re.match(r"^\t/\* .*\*/$", line):
                            continue
                        if line == "#ifdef __CHECKER__":
                            state = "in_enum/ifdef_checker"
                            continue
                        if matches := re.match(
                            r"^\t([0-9A-Z_]+)\s*= (?:\(__force [0-9a-zA-Z_]+\))?([0-9a-fA-Fx]+),(?: /\*.*\*/)?$", line
                        ):
                            if verbose:
                                print(f"    {line}")
                            name, value_s = matches.groups()
                            value = int(value_s, 0)
                            current_enum_last_value = value

                            if current_enum_prefix:
                                if not name.startswith(current_enum_prefix):
                                    raise ValueError(
                                        f"Mismatched prefix: {current_enum_cls.__name__}.{name} = {value:#x}, not {current_enum_prefix!r}"  # noqa
                                    )
                                name = name[len(current_enum_prefix):]
                            if current_enum_suffix:
                                if not name.endswith(current_enum_suffix):
                                    raise ValueError(
                                        f"Mismatched suffix: {current_enum_cls.__name__}.{name} = {value:#x}, not {current_enum_suffix!r}"  # noqa
                                    )
                                name = name[:-len(current_enum_suffix)]

                            if current_enum_cls == GROUP_CMD_ENUM[MvmCommandGroups.LEGACY] and name == "REPLY_MAX":
                                # Ignore old REPLY_MAX
                                if value != 0xFF:
                                    raise ValueError(
                                        f"Mismatched value: {current_enum_cls.__name__}.{name} = 0xff, not {value:#x}"
                                    )
                                continue

                            # Update values to new ones, for some items
                            if current_enum_prefix == "IWL_UCODE_TLV_CAPA_":
                                if name == "LED_CMD_SUPPORT" and value == 86:
                                    value = 88
                                elif name == "RFIM_SUPPORT" and value == 102:
                                    value = 62

                            try:
                                cur_item = (
                                    current_enum_cls.from_name(name)
                                    if hasattr(current_enum_cls, "from_name")
                                    else getattr(current_enum_cls, name)
                                )
                            except AttributeError:
                                raise ValueError(
                                    f"Missing {current_enum_cls.__name__}.{name} = {value:#x} from {file_name} {commit_hash} line {line!r}"  # noqa
                                )
                            if cur_item.value != value:
                                raise ValueError(
                                    f"Mismatched value: {current_enum_cls.__name__}.{name} = {cur_item.value:#x}, not {value:#x}"  # noqa
                                )
                            continue
                        if matches := re.match(r"^\t([0-9A-Z_]+),?(?: /\*.*\*/)?$", line):
                            # Enum item with no explicit value
                            if verbose:
                                print(f"    {line}")
                            (name,) = matches.groups()
                            assert isinstance(current_enum_last_value, int)
                            current_enum_last_value += 1
                            value = current_enum_last_value

                            if current_enum_prefix == "IWL_FW_INI_REGION_" and name == "IWL_FW_INI_REGION_NUM":
                                # Ignore IWL_FW_INI_REGION_NUM
                                continue

                            if (
                                current_enum_prefix == "IWL_FW_INI_ALLOCATION_ID_"
                                and name == "IWL_FW_INI_ALLOCATION_NUM"
                            ):
                                # Ignore IWL_FW_INI_ALLOCATION_NUM
                                continue

                            if current_enum_prefix == "IWL_FW_INI_LOCATION_" and name == "IWL_FW_INI_LOCATION_NUM":
                                # Ignore IWL_FW_INI_LOCATION_NUM
                                continue

                            if current_enum_prefix == "IWL_UCODE_TLV_API_" and name == "NUM_IWL_UCODE_TLV_API":
                                # Ignore NUM_IWL_UCODE_TLV_API
                                continue

                            if current_enum_prefix == "IWL_UCODE_TLV_CAPA_" and name == "NUM_IWL_UCODE_TLV_CAPA":
                                # Ignore NUM_IWL_UCODE_TLV_CAPA
                                continue

                            if current_enum_prefix == "IWL_UCODE_" and name == "IWL_UCODE_TYPE_MAX":
                                # Ignore IWL_UCODE_TYPE_MAX
                                continue

                            if current_enum_prefix:
                                if name.startswith(current_enum_prefix):
                                    name = name[len(current_enum_prefix):]
                                elif (
                                    current_enum_prefix == "IWL_FW_INI_ALLOCATION_ID_"
                                    and name == "IWL_FW_INI_ALLOCATION_INVALID"
                                ):
                                    # Special case
                                    name = "INVALID"
                                else:
                                    raise ValueError(
                                        f"Mismatched prefix: {current_enum_cls.__name__}.{name} = {value:#x}, not {current_enum_prefix!r}"  # noqa
                                    )
                            if current_enum_suffix:
                                if not name.endswith(current_enum_suffix):
                                    raise ValueError(
                                        f"Mismatched suffix: {current_enum_cls.__name__}.{name} = {value:#x}, not {current_enum_suffix!r}"  # noqa
                                    )
                                name = name[:-len(current_enum_suffix)]

                            # Switch the enum to OldFwIniRegionType if DEVICE_MEMORY is the old value
                            if (
                                current_enum_cls == parse_intel_wifi_fw.FwIniRegionType
                                and name == "DEVICE_MEMORY"
                                and value == 1
                            ):
                                assert (
                                    c_enums["iwl_fw_ini_region_type"] == parse_intel_wifi_fw.FwIniRegionType
                                )  # Sanity check
                                assert c_enums["old:iwl_fw_ini_region_type"] == parse_intel_wifi_fw.OldFwIniRegionType
                                current_enum_cls = parse_intel_wifi_fw.OldFwIniRegionType

                            # Switch the enum to OldUcodeType if IWL_UCODE_NONE is present
                            if current_enum_cls == parse_intel_wifi_fw.UcodeType and name == "NONE" and value == 0:
                                assert c_enums["iwl_ucode_type"] == parse_intel_wifi_fw.UcodeType  # Sanity check
                                assert c_enums["old:iwl_ucode_type"] == parse_intel_wifi_fw.OldUcodeType
                                current_enum_cls = parse_intel_wifi_fw.OldUcodeType

                            try:
                                cur_item = (
                                    current_enum_cls.from_name(name)
                                    if hasattr(current_enum_cls, "from_name")
                                    else getattr(current_enum_cls, name)
                                )
                            except AttributeError:
                                raise ValueError(
                                    f"Missing {current_enum_cls.__name__}.{name} = {value:#x} from {file_name} {commit_hash} line {line!r}"  # noqa
                                )
                            if cur_item.value != value:
                                raise ValueError(
                                    f"Mismatched value: {current_enum_cls.__name__}.{name} = {cur_item.value:#x}, not {value:#x}"  # noqa
                                )
                            continue
                        if current_enum_prefix == "IWL_UCODE_TLV_":
                            if line in {
                                "\tIWL_UCODE_TLV_DEBUG_BASE = IWL_UCODE_TLV_TYPE_BUFFER_ALLOCATION,",
                                "\tIWL_UCODE_TLV_DEBUG_BASE\t\t= IWL_UCODE_INI_TLV_GROUP,",
                                "\tIWL_UCODE_TLV_DEBUG_MAX = IWL_UCODE_TLV_TYPE_DEBUG_FLOW,",
                                "\tIWL_UCODE_TLV_DEBUG_MAX = IWL_UCODE_TLV_TYPE_TRIGGERS,",
                            }:
                                # Skip the lines which defined IWL_UCODE_TLV_... directly from other enum values
                                continue
                            if matches := re.match(
                                r"^\tIWL_UCODE_TLV_([0-9A-Z_]+)\s*= IWL_UCODE_TLV_CONST_BASE [+] ([0-9a-fA-Fx]+),$",
                                line,
                            ):
                                # Match "IWL_UCODE_TLV_FW_NUM_STATIONS = IWL_UCODE_TLV_CONST_BASE + 0,"
                                if verbose:
                                    print(f"    {line}")
                                name, value_s = matches.groups()
                                value = int(value_s, 0)
                                assert value < 0x100
                                value += 0x100
                                current_enum_last_value = value

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
                            if matches := re.match(
                                r"^\tIWL_UCODE_TLV_([0-9A-Z_]+)\s*= IWL_UCODE_INI_TLV_GROUP [|+] ([0-9a-fA-Fx]+),$",
                                line,
                            ):
                                # Match "IWL_UCODE_TLV_TYPE_BUFFER_ALLOCATION = IWL_UCODE_INI_TLV_GROUP | 0x1,"
                                if verbose:
                                    print(f"    {line}")
                                name, value_s = matches.groups()
                                value = int(value_s, 0)
                                assert value < 0x1000000
                                value += 0x1000000
                                current_enum_last_value = value
                                name = "OLD_" + name

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
                            if matches := re.match(
                                r"^\tIWL_UCODE_TLV_([0-9A-Z_]+)\s*= IWL_UCODE_TLV_DEBUG_BASE \+ ([0-9a-fA-Fx]+),$",
                                line,
                            ):
                                # Match "IWL_UCODE_TLV_TYPE_DEBUG_INFO = IWL_UCODE_TLV_DEBUG_BASE + 0,"
                                if verbose:
                                    print(f"    {line}")
                                name, value_s = matches.groups()
                                value = int(value_s, 0)
                                assert value < 0x1000000
                                value += 0x1000005
                                current_enum_last_value = value

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
                        if current_enum_prefix in {"IWL_UCODE_TLV_CAPA_", "IWL_UCODE_TLV_FLAGS_", "IWL_UCODE_TLV_API_"}:
                            if matches := re.match(
                                r"^\s*([0-9A-Z_]+)\s*= BIT\(([0-9a-fA-Fx]+)\),$",
                                line,
                            ):
                                # Match "IWL_UCODE_TLV_CAPA_D0I3_SUPPORT = BIT(0),"
                                if verbose:
                                    print(f"    {line}")
                                name, value_s = matches.groups()
                                value = int(value_s, 0)
                                current_enum_last_value = value
                                if name.startswith(current_enum_prefix):
                                    name = name[len(current_enum_prefix):]
                                elif (
                                    current_enum_prefix == "IWL_UCODE_TLV_API_"
                                    and name == "IWL_UCODE_TLV_CAPA_EXTENDED_BEACON"
                                ):
                                    # Special case
                                    name = "CAPA_EXTENDED_BEACON"
                                else:
                                    raise ValueError(
                                        f"Mismatched prefix: {current_enum_cls.__name__}.{name} = {value:#x}, not {current_enum_prefix!r}"  # noqa
                                    )

                                try:
                                    cur_item = (
                                        current_enum_cls.from_name(name)
                                        if hasattr(current_enum_cls, "from_name")
                                        else getattr(current_enum_cls, name)
                                    )
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
                    elif state == "in_enum/ifdef_checker":
                        if line == "#endif":
                            state = "in_enum"
                            continue
                        if re.match(r"^\t+/\* .*\*/$", line):
                            continue
                        if line in {
                            "\t\t= 128",
                            "#define NUM_IWL_UCODE_TLV_API 128",
                            "#define NUM_IWL_UCODE_TLV_CAPA 128",
                            "#else",
                            "\tNUM_IWL_UCODE_TLV_API",
                            "\tNUM_IWL_UCODE_TLV_CAPA",
                        }:
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
