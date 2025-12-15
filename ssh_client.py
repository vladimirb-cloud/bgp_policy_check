import os
import json
import logging
from typing import List, Dict
from netmiko import ConnectHandler
from .utils import is_private_asn
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class VendorParser:
    def parse_bgp_output(self, output: str) -> List[Dict]:
        raise NotImplementedError


class JuniperParser(VendorParser):
    def parse_bgp_output(self, output: str) -> List[Dict]:
        try:
            data = json.loads(output)
        except Exception as e:
            logger.error(f"Failed to parse JSON BGP output: {e}")
            return []

        peers = []
        bgp_info = data.get("bgp-information", [])
        if not bgp_info:
            return []

        for peer in bgp_info[0].get("bgp-peer", []):
            try:
                peer_ip_raw = peer.get("peer-address", [{}])[0].get("data", "")
                # Убираем порт, если есть (например, 1.2.3.4+179)
                peer_ip = peer_ip_raw.split('+')[0]

                remote_as_raw = peer.get("peer-as", [{}])[0].get("data", "0")
                remote_as = int(remote_as_raw)
                state = peer.get("peer-state", [{}])[0].get("data", "unknown")

                if is_private_asn(remote_as):
                    continue

                # Ищем только RIBs, относящиеся к instance internet
                rib_list = peer.get("bgp-rib", [])
                afi = None
                for rib in rib_list:
                    rib_name_raw = rib.get("name", [{}])[0].get("data", "")
                    if rib_name_raw == "internet.inet.0":
                        afi = "ipv4"
                        break
                    elif rib_name_raw == "internet.inet6.0":
                        afi = "ipv6"
                        break

                # Если нет нужного RIB, пропускаем (не добавляем пира)
                if afi is None:
                    continue

                peers.append({
                    "peer_ip": peer_ip,
                    "remote_as": remote_as,
                    "afi": afi,
                    "state": state,
                    "raw": peer
                })
            except Exception as e:
                logger.warning(f"Failed to parse peer from JSON: {e}")
                continue
        return peers

class AristaParser(VendorParser):
    def parse_bgp_output(self, text: str) -> List[Dict]:
        peers = []
        for line in text.splitlines():
            # Пример строки Arista IPv4:
            # 10.0.0.2          4    65000  10000  10000    0    0 00:05:12 40  Established
            m4 = re.match(
                r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+)",
                line
            )
            if m4:
                peer_ip = m4.group(1)
                remote_as = int(m4.group(2))
                state = m4.group(3)

                if is_private_asn(remote_as):
                    continue

                peers.append({
                    "peer_ip": peer_ip,
                    "remote_as": remote_as,
                    "afi": "ipv4",
                    "state": state,
                    "raw": line
                })

            # Пример Arista IPv6:
            # 2001:db8::2       4    65000  10000  10000    0    0 00:05:12 40  Established
            m6 = re.match(
                r"\s*([0-9a-fA-F:]+(?:::[0-9a-fA-F:]*)?)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+)",
                line
            )
            if m6:
                peer_ip = m6.group(1)
                remote_as = int(m6.group(2))
                state = m6.group(3)

                if is_private_asn(remote_as):
                    continue

                peers.append({
                    "peer_ip": peer_ip,
                    "remote_as": remote_as,
                    "afi": "ipv6",
                    "state": state,
                    "raw": line
                })
        return peers

class CiscoParser(VendorParser):
    def parse_bgp_output(self, text: str) -> List[Dict]:
        peers = []
        for line in text.splitlines():
            # Пример строки Cisco IPv4:
            # 10.0.0.2    4    65000    10000    10000    0    0    00:05:12 40  Established
            m4 = re.match(
                r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)",
                line
            )
            if m4:
                peer_ip = m4.group(1)
                remote_as = int(m4.group(2))
                state = m4.group(3)

                if is_private_asn(remote_as):
                    continue

                peers.append({
                    "peer_ip": peer_ip,
                    "remote_as": remote_as,
                    "afi": "ipv4",
                    "state": state,
                    "raw": line
                })

            # Пример Cisco IPv6:
            # 2001:db8::2 4    65000    10000    10000    0    0    00:05:12 40  Established
            m6 = re.match(
                r"\s*([0-9a-fA-F:]+(?:::[0-9a-fA-F:]*)?)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)",
                line
            )
            if m6:
                peer_ip = m6.group(1)
                remote_as = int(m6.group(2))
                state = m6.group(3)

                if is_private_asn(remote_as):
                    continue

                peers.append({
                    "peer_ip": peer_ip,
                    "remote_as": remote_as,
                    "afi": "ipv6",
                    "state": state,
                    "raw": line
                })
        return peers

PARSER_MAP = {
    "juniper_junos": JuniperParser(),
    "arista_eos": AristaParser(),
    "cisco_ios": CiscoParser(),
}

def detect_vendor(conn):
    output = conn.send_command("show version")
    if "Arista" in output:
        return "arista_eos"
    elif "Juniper" in output or "junos" in output.lower():
        return "juniper_junos"
    elif "Cisco IOS" in output or "IOS-XE" in output or "IOS-XR" in output:
        return "cisco_ios"
    else:
        logger.warning("Could not detect vendor from 'show version'. Defaulting to juniper_junos.")
        return "juniper_junos"

def gather_bgp_from_router(router: Dict) -> List[Dict]:
    device = {
        "device_type": "autodetect",
        "host": router["host"],
        "username": router["user"],
        "port": router.get("port", 22)
    }

    auth = router.get("auth_method", "password")
    password_or_key = router["password"]

    if password_or_key.startswith("$"):
        var_name = password_or_key[1:]
        real_password = os.getenv(var_name)
        if real_password is None:
            raise ValueError(f"Environment variable {var_name} is not defined.")
    else:
        real_password = password_or_key

    if auth == "password":
        device["password"] = real_password
    else:
        device["use_keys"] = True
        device["key_file"] = real_password

    try:
        conn = ConnectHandler(**device)
    except Exception as e:
        logger.error(f"SSH connection failed to {router['host']}: {e}")
        raise

    vendor = detect_vendor(conn)

    if vendor == "juniper_junos":
        # Используем JSON-вывод для Juniper, только instance internet
        output = conn.send_command("show bgp summary instance internet | display json | no-more")
    elif vendor == "arista_eos":
        output = conn.send_command("show ip bgp summary vrf internet")
    elif vendor == "cisco_ios":
        output = conn.send_command("show ip bgp summary")
    else:
        output = conn.send_command("show bgp summary")

    conn.disconnect()

    parser = PARSER_MAP.get(vendor, JuniperParser())
    return parser.parse_bgp_output(output)