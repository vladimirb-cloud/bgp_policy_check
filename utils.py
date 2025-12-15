import ipaddress
import re
from typing import List

PRIVATE_ASN_RANGES = [(64512, 65534)]

def is_private_asn(asn: int) -> bool:
    for a, b in PRIVATE_ASN_RANGES:
        if a <= asn <= b:
            return True
    return False

def check_special_addresses(peer_ip: str, cidr: str) -> List[str]:
    issues = []
    if not peer_ip:
        issues.append("no_peer_ip_parsed")
        return issues
    try:
        ip = ipaddress.IPv4Address(peer_ip)
    except Exception:
        issues.append("invalid_ip")
        return issues

    if cidr:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            if ip == net.network_address:
                issues.append("is_network_address")
            if ip == net.broadcast_address:
                issues.append("is_broadcast_address")
        except Exception:
            pass
    else:
        last_octet = int(peer_ip.split(".")[-1])
        if last_octet == 0:
            issues.append("ends_with_.0_suspicious")
        if last_octet == 255:
            issues.append("ends_with_.255_suspicious")
    return issues

# Regex patterns
RE_ASN = re.compile(r"(?:AS)?\s*(\d+)", re.IGNORECASE)
RE_CIDR = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})")
RE_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
RE_PEERING_LINE = re.compile(
    r"(?P<asn>AS?\d+)\s+(?P<peer>\d{1,3}(?:\.\d{1,3}){3})(?:\s+at\s+(?P<local>\d{1,3}(?:\.\d{1,3}){3}))?",
    flags=re.IGNORECASE
)