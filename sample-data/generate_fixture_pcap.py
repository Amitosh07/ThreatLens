"""Write the synthetic lab fixture used to demonstrate ThreatLens offline."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.utils.synthetic_pcap import write_demo_pcap


def main() -> None:
    destination = Path(__file__).resolve().parent / "synthetic-lab-fixture.pcap"
    write_demo_pcap(destination)
    print(f"Wrote {destination} ({destination.stat().st_size} bytes)")
    print("This file is synthetic lab traffic, not a recording of a real attack.")


if __name__ == "__main__":
    main()
