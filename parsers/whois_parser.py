import subprocess
import ipaddress
import re
import logging
import os
from typing import List, Dict
from ..config import Config
from ..utils import is_private_asn, check_special_addresses

logger = logging.getLogger(__name__)

# Регулярки
RE_IPV4 = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
RE_IPV6 = re.compile(r"([0-9a-fA-F:]+(?:::[0-9a-fA-F:]*)?)")
RE_ASN = re.compile(r"AS(\d+)")

# Для строк вида: mp-import: afi ipv4.unicast from ASxxxx at <ip>
RE_IMPORT_IPV4 = re.compile(
    r"mp-import:\s+afi\s+ipv4\.unicast\s+from\s+AS(\d+)\s+at\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)
RE_IMPORT_IPV6 = re.compile(
    r"mp-import:\s+afi\s+ipv6\.unicast\s+from\s+AS(\d+)\s+at\s+([0-9a-fA-F:]+(?:::[0-9a-fA-F:]*)?)",
    re.IGNORECASE
)

# Для строк вида: from ASxxxx at <ip> action ...
RE_IMPORT_SHORT = re.compile(
    r"from\s+AS(\d+)\s+at\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)

def fetch_and_parse_whois(as_number: str, rr_host: str, config: Config) -> List[Dict]:
    cache_file = os.path.join(config.cache_dir, f"whois_AS{as_number}_{rr_host.replace('.', '_')}.txt")

    if os.path.exists(cache_file):
        logger.info(f"Using cached whois data from {cache_file}")
        with open(cache_file, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        cmd = ["whois", "-h", rr_host, f"AS{as_number}"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            text = result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to fetch whois data from {rr_host}: {e}")
            raise

        logger.info(f"Fetched {len(text)} characters from {rr_host} for AS{as_number}")

        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info(f"Saved whois data to cache: {cache_file}")

    results = []

    # 1. mp-import: afi ipv4.unicast from ASxxxx at <ipv4>
    for m in RE_IMPORT_IPV4.finditer(text):
        asn = int(m.group(1))
        peer_ip = m.group(2)
        results.append({
            "asn": asn,
            "peer_ip": peer_ip,
            "afi": "ipv4",
            "raw": m.group(0)
        })

    # 2. mp-import: afi ipv6.unicast from ASxxxx at <ipv6>
    for m in RE_IMPORT_IPV6.finditer(text):
        asn = int(m.group(1))
        peer_ip = m.group(2)
        results.append({
            "asn": asn,
            "peer_ip": peer_ip,
            "afi": "ipv6",
            "raw": m.group(0)
        })

    # 3. from ASxxxx at <ipv4>
    for m in RE_IMPORT_SHORT.finditer(text):
        asn = int(m.group(1))
        peer_ip = m.group(2)
        results.append({
            "asn": asn,
            "peer_ip": peer_ip,
            "afi": "ipv4",
            "raw": m.group(0)
        })

    # Filter and dedup
    filtered = []
    seen = set()
    for r in results:
        if config.exclude_private_asns and is_private_asn(r["asn"]):
            continue

        peer_ip = r["peer_ip"]
        if not peer_ip:
            continue

        # Проверим, IPv4 или IPv6
        afi = r["afi"]
        if afi == "ipv4":
            try:
                peer_ip = str(ipaddress.IPv4Address(peer_ip))
            except Exception:
                continue
        elif afi == "ipv6":
            try:
                peer_ip = str(ipaddress.IPv6Address(peer_ip))
            except Exception:
                continue
        else:
            continue

        # нормализуем (важно для сравнения строк, особенно IPv6)
        r["peer_ip"] = peer_ip

        # Исключаем broadcast и network (.0 / .255) для IPv4
        if afi == "ipv4":
            last_octet = int(peer_ip.split(".")[-1])
            if last_octet == 0 or last_octet == 255:
                continue

        key = (r["asn"], r["peer_ip"], r.get("afi"))
        if key in seen:
            continue
        seen.add(key)

        r["issues"] = check_special_addresses(r["peer_ip"], None)
        filtered.append(r)

    return filtered