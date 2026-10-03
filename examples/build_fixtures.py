import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.fixtures.elf_generator import (
    create_vulnerable_fixture,
    create_fixed_fixture,
    create_negative_fixture,
)



def main():
    root = Path(__file__).resolve().parent

    vuln_path = root / "vulnerable" / "firmware.elf"
    fixed_path = root / "fixed" / "firmware_fixed.elf"
    neg_path = root / "negative" / "firmware_safe.elf"

    create_vulnerable_fixture(vuln_path)
    create_fixed_fixture(fixed_path)
    create_negative_fixture(neg_path)

    print(f"Generated {vuln_path}")
    print(f"Generated {fixed_path}")
    print(f"Generated {neg_path}")


if __name__ == "__main__":
    main()
