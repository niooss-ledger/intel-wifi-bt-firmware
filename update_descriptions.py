#!/usr/bin/env python3
"""Update the description of all downloaded firmware files"""
from pathlib import Path

from parse_intel_wifi_fw import IntelWifiFirmware


BASE_PATH = Path(__file__).parent
DESCRIPTIONS_PATH = BASE_PATH / "descriptions"


def update_descriptions() -> None:
    for file_path in BASE_PATH.glob("intel_wifi/**/*"):
        if not file_path.is_file():
            continue
        if file_path.name in {"README.md", "LICENSE"}:
            continue

        desc_file = DESCRIPTIONS_PATH / file_path.relative_to(BASE_PATH)
        desc_file.parent.mkdir(parents=True, exist_ok=True)

        print(f"Parsing {file_path}")
        all_fw = list(IntelWifiFirmware.parse_all_file(file_path))
        if len(all_fw) == 1:
            # The file contained a single firmware
            desc_file = desc_file.parent / f"{desc_file.name}.txt"
            fw = all_fw[0]
            with desc_file.open("w") as fout:
                fw.print_header(out=fout)
                for entry in fw.entries:
                    fw.print_entry(entry, out=fout)
        else:
            # Split the firmware file
            for idx, fw in enumerate(all_fw):
                part_desc_file = desc_file.parent / f"{desc_file.name}_part_{idx:03d}.txt"
                with part_desc_file.open("w") as fout:
                    fw.print_header(out=fout)
                    for entry in fw.entries:
                        fw.print_entry(entry, out=fout)


if __name__ == "__main__":
    update_descriptions()