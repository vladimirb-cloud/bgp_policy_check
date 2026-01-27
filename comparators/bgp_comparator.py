import re
from typing import List, Dict, Tuple
from ..ssh_client import gather_bgp_from_router
from ..config import Config


def compare_policies_to_routers(
    policies: List[Dict],
    routers_info: List[Dict],
    config: Config
) -> Tuple[List[Dict], Dict]:
    """
    Сравнивает политики BGP с текущими BGP-пирами на устройствах.
    Возвращает список инцидентов и статистику BGP-сессий.
    """
    incidents = []

    # --- Инициализация статистики BGP ---
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

    # --- Фильтр политик по AFI ---
    filtered_policies = policies
    if config.afi_filter != "all":
        filtered_policies = [p for p in policies if p.get("afi", "ipv4") == config.afi_filter]

    # --- Индекс политик: (peer_ip, afi) -> expected AS ---
    policy_by_peer: Dict[tuple, set] = {}
    policy_by_asn: Dict[tuple, set] = {}
    for p in filtered_policies:
        asn = p.get("asn")
        afi = p.get("afi", "ipv4")
        peer_ip = p.get("peer_ip")
        if not asn or not peer_ip:
            continue

        policy_by_peer.setdefault((peer_ip, afi), set()).add(int(asn))
        policy_by_asn.setdefault((int(asn), afi), set()).add(peer_ip)

    # --- Обход всех роутеров ---
    if not getattr(config, "ssh_enabled", True):
        return [], bgp_stats

    for router in routers_info:
        try:
            neighbors = gather_bgp_from_router(router)
        except Exception as e:
            incidents.append({"router": router["name"], "issue": "ssh_failed", "details": str(e)})
            continue

        present_peers = set()
        for n in neighbors:
            peer_ip = n.get("peer_ip")
            state = n.get("state", "")
            afi = n.get("afi", "ipv4")
            raw = n.get("raw", {})

            # Берем реальный ASN из raw, fallback на n.get("remote_as")
            peer_asn = raw.get("peerAsn", n.get("remote_as", 0))
            try:
                peer_asn_int = int(peer_asn)
            except Exception:
                peer_asn_int = 0

            # Пропускаем, если фильтр AFI включен
            if config.afi_filter != "all" and afi != config.afi_filter:
                continue

            if not peer_ip:
                incidents.append({
                    "router": router["name"],
                    "peer": None,
                    "issue": "neighbor_no_ip_parsed",
                    "details": raw
                })
                continue

            present_peers.add((peer_ip, afi))
            bgp_stats["total"] += 1
            expected_asns = policy_by_peer.get((peer_ip, afi))
            expected_ips = policy_by_asn.get((peer_asn_int, afi))
            asn_in_policy = expected_ips is not None

            # --- Обновление статистики ---
            if afi in bgp_stats["afi"]:
                bgp_stats["afi"][afi]["total"] += 1
                states_dict = bgp_stats["afi"][afi]["states"]

                state_key = (
                    "Established" if re.search(r"Estab|Established", state, re.IGNORECASE) else
                    "Active" if re.search(r"Active", state, re.IGNORECASE) else
                    "Connect" if re.search(r"Connect", state, re.IGNORECASE) else
                    "Idle" if re.search(r"Idle", state, re.IGNORECASE) else None
                )

                if state_key:
                    states_dict[state_key]["total"] += 1
                    # В статистике считаем "with_policy" как "ASN есть в политике"
                    if not asn_in_policy:
                        states_dict[state_key]["without_policy"] += 1
                    else:
                        states_dict[state_key]["with_policy"] += 1
                else:
                    bgp_stats["other"] += 1
            else:
                bgp_stats["other"] += 1

            # --- Формирование инцидентов ---
            # проверяем по ASN
            if expected_ips is None:
                # ASN + AFI нет в политике → neighbor_not_in_policy
                incidents.append({
                    "router": router["name"],
                    "peer": peer_ip,
                    "issue": "neighbor_not_in_policy",
                    "remote_as": peer_asn,
                    "afi": afi,
                    "state": state,
                    "details": raw
                })
            elif peer_ip not in expected_ips:
                # ASN есть, но IP отличается → отдельный инцидент
                incidents.append({
                    "router": router["name"],
                    "peer": peer_ip,
                    "issue": "ip_mismatch_in_policy",
                    "remote_as": peer_asn,
                    "afi": afi,
                    "state": state,
                    "details": f"Policy ASN {peer_asn} exists, but IP {peer_ip} not listed in policy"
                })
            # если peer_ip в expected_ips → всё ок, инцидентов не добавляем

            else:
                if expected_asns is not None and int(peer_asn) not in expected_asns:
                    incidents.append({
                        "router": router["name"],
                        "peer": peer_ip,
                        "issue": "asn_mismatch",
                        "remote_as": peer_asn,
                        "expected_as": sorted(expected_asns) if expected_asns else None,
                        "afi": afi,
                        "state": state,
                        "details": raw
                    })
                if not re.search(r"Estab|Established", str(state), re.IGNORECASE):
                    incidents.append({
                        "router": router["name"],
                        "peer": peer_ip,
                        "issue": "session_not_established",
                        "remote_as": peer_asn,
                        "expected_as": sorted(expected_asns) if expected_asns else None,
                        "afi": afi,
                        "state": state,
                        "details": raw
                    })

        # --- Проверка пиров, которые есть в политике, но отсутствуют на роутере ---
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
