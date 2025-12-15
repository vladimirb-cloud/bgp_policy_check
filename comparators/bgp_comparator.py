import re
from typing import List, Dict, Tuple
from ..ssh_client import gather_bgp_from_router
from ..config import Config


def compare_policies_to_routers(policies: List[Dict], routers_info: List[Dict], config: Config) -> Tuple[
    List[Dict], Dict]:
    incidents = []
    # Статистика: { afi: { state: {"total": N, "with_policy": M, "without_policy": K} } }
    bgp_stats = {
        "total": 0,
        "afi": {
            "ipv4": {
                "states": {
                    "Established": {"total": 0, "with_policy": 0, "without_policy": 0},
                    "Active": {"total": 0, "with_policy": 0, "without_policy": 0},
                    "Connect": {"total": 0, "with_policy": 0, "without_policy": 0},
                    "Idle": {"total": 0, "with_policy": 0, "without_policy": 0},
                },
                "total": 0
            },
            "ipv6": {
                "states": {
                    "Established": {"total": 0, "with_policy": 0, "without_policy": 0},
                    "Active": {"total": 0, "with_policy": 0, "without_policy": 0},
                    "Connect": {"total": 0, "with_policy": 0, "without_policy": 0},
                    "Idle": {"total": 0, "with_policy": 0, "without_policy": 0},
                },
                "total": 0
            },
        },
        "other": 0
    }

    # Фильтр политик по AFI
    filtered_policies = policies
    if config.afi_filter != "all":
        filtered_policies = [p for p in policies if p.get("afi", "ipv4") == config.afi_filter]

    # Индекс: (peer_ip, afi) -> asn
    policy_index = {}
    for p in filtered_policies:
        peer_ip = p.get("peer_ip")
        afi = p.get("afi", "ipv4")
        if peer_ip:
            policy_index[(peer_ip, afi)] = p["asn"]

    for router in routers_info:
        try:
            neighbors = gather_bgp_from_router(router)
        except Exception as e:
            incidents.append({"router": router["name"], "issue": "ssh_failed", "details": str(e)})
            continue

        present_peers = set()
        for n in neighbors:
            peer_ip = n.get("peer_ip")
            remote_as = n.get("remote_as")
            state = n.get("state", "")
            afi = n.get("afi", "ipv4")  # "ipv4", "ipv6", или "other"

            # Пропускаем, если фильтр AFI активен и не совпадает
            if config.afi_filter != "all" and afi != config.afi_filter:
                continue

            raw = n.get("raw")
            if not peer_ip:
                incidents.append(
                    {"router": router["name"], "peer": None, "issue": "neighbor_no_ip_parsed", "details": raw})
                continue

            present_peers.add((peer_ip, afi))

            # Обновляем статистику
            bgp_stats["total"] += 1
            expected_as = policy_index.get((peer_ip, afi))

            if afi in bgp_stats["afi"]:
                bgp_stats["afi"][afi]["total"] += 1
                states = bgp_stats["afi"][afi]["states"]
                if re.search(r"Estab|Established", state, re.IGNORECASE):
                    states["Established"]["total"] += 1
                    if expected_as is None:
                        states["Established"]["without_policy"] += 1
                    else:
                        states["Established"]["with_policy"] += 1
                elif re.search(r"Active", state, re.IGNORECASE):
                    states["Active"]["total"] += 1
                    if expected_as is None:
                        states["Active"]["without_policy"] += 1
                    else:
                        states["Active"]["with_policy"] += 1
                elif re.search(r"Connect", state, re.IGNORECASE):
                    states["Connect"]["total"] += 1
                    if expected_as is None:
                        states["Connect"]["without_policy"] += 1
                    else:
                        states["Connect"]["with_policy"] += 1
                elif re.search(r"Idle", state, re.IGNORECASE):
                    states["Idle"]["total"] += 1
                    if expected_as is None:
                        states["Idle"]["without_policy"] += 1
                    else:
                        states["Idle"]["with_policy"] += 1
                else:
                    bgp_stats["other"] += 1
            else:
                # Если afi == "other", можно либо игнорировать, либо тоже учитывать
                # Для совместимости, будем считать как "other"
                bgp_stats["other"] += 1

            if expected_as is None:
                incidents.append({
                    "router": router["name"],
                    "peer": peer_ip,
                    "issue": "neighbor_not_in_policy",
                    "remote_as": remote_as,
                    "afi": afi,
                    "state": state,
                    "details": raw
                })
            else:
                if remote_as != expected_as:
                    incidents.append({
                        "router": router["name"],
                        "peer": peer_ip,
                        "issue": "asn_mismatch",
                        "remote_as": remote_as,
                        "expected_as": expected_as,
                        "afi": afi,
                        "state": state,
                        "details": raw
                    })
                if not re.search(r"Estab|Established", str(state), re.IGNORECASE):
                    incidents.append({
                        "router": router["name"],
                        "peer": peer_ip,
                        "issue": "session_not_established",
                        "remote_as": remote_as,
                        "expected_as": expected_as,
                        "afi": afi,
                        "state": state,
                        "details": raw
                    })

        for p in filtered_policies:
            peer_ip = p["peer_ip"]
            afi = p.get("afi", "ipv4")
            if config.afi_filter != "all" and afi != config.afi_filter:
                continue
            if peer_ip and (peer_ip, afi) not in present_peers:
                incidents.append({
                    "router": router["name"],
                    "peer": peer_ip,
                    "issue": "policy_peer_not_present_on_router",
                    "expected_as": p["asn"],
                    "afi": afi,
                    "state": None,
                    "details": p.get("raw")
                })

    return incidents, bgp_stats