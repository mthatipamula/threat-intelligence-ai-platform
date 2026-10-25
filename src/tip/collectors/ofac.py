"""OFAC-sanctioned crypto addresses (US Treasury SDN list), via the 0xB10C extraction published per chain.

Each address becomes an Indicator. Sending funds to one is a sanctions violation, so the platform checks withdrawal
logs against these. The SDN list doesn't say which sanctioned party each address belongs to in this extraction, so the
indicators are labelled "sanctioned", not attributed to an actor.
"""

from pathlib import Path
from typing import Any

from tip import stix
from tip.collectors.base import Collected, fetch

BASE = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists"
# Chains a crypto exchange typically supports; the published list also has smaller ones.
CHAINS = ["XBT", "ETH", "USDT", "USDC", "TRX", "SOL", "BSC", "ARB", "LTC", "BCH", "XMR", "ZEC", "ETC", "XRP"]


def addresses(text: str) -> set[str]:
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}


def build(chains_by_address: dict[str, list[str]]) -> list[Any]:
    """One Indicator per address. The same address can be sanctioned on several chains (an 0x address for ETH, USDT
    and USDC), so it lists all of them rather than letting one chain's entry overwrite another's."""
    out: list[Any] = []
    for address, chains in sorted(chains_by_address.items()):
        listed = ", ".join(chains)
        out.append(
            stix.indicator(
                "ofac",
                "crypto-wallet",
                address,
                name=f"OFAC-sanctioned address {address} ({listed})",
                description=f"Listed on the US Treasury OFAC SDN list for {listed}. Transfers to it are prohibited.",
                indicator_types=["attribution"],
                labels=["sanctioned", *(f"chain:{c.lower()}" for c in chains)],
                confidence=95,
                reference_url=f"{BASE}/sanctioned_addresses_{chains[0]}.txt",
                extra={"x_tip_chains": chains},
            )
        )
    return out


def collect(cache_dir: Path | None = None) -> Collected:
    chains_by_address: dict[str, list[str]] = {}
    per_chain = []
    for chain in CHAINS:
        name = f"ofac_{chain}.txt"
        path = cache_dir / name if cache_dir else fetch(f"{BASE}/sanctioned_addresses_{chain}.txt", name)
        found = addresses(path.read_text())
        for address in found:
            chains_by_address.setdefault(address, []).append(chain)
        per_chain.append(f"{chain} {len(found)}")
    objects: list[Any] = [stix.identity("ofac"), *build(chains_by_address)]
    return Collected(objects, f"{len(objects) - 1} unique sanctioned addresses ({', '.join(per_chain)})")
