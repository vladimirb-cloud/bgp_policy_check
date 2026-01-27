import csv
import json
from typing import List, Dict
from ..config import Config

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

def write_yaml_report(policies: List[Dict], incidents: List[Dict], config: Config, bgp_stats: Dict):
    if yaml is None:
        raise RuntimeError("PyYAML is not installed; cannot write YAML report.")
    data = {
        "summary": {
            "total_policy_peers": len([p for p in policies if p.get("peer_ip")]),
            "total_incidents": len(incidents)
        },
        "bgp_sessions_summary": {
            "afi": bgp_stats["afi"],
            "total_sessions": bgp_stats["total"],
            "other_sessions": bgp_stats["other"]
        },
        "incidents": incidents,
        "notes": [
            "ASNs in range 64512–65534 и AS65500 были исключены как приватные.",
            "Адреса с сетевыми (.0) или broadcast (.255) помечены как подозрительные, если известен CIDR.",
            "Если netmiko не установлен, SSH-проверка не выполняется."
        ]
    }
    with open(config.report_yaml, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def _format_details(details) -> str:
    det_str = "N/A"

    if isinstance(details, dict):
        # Arista формат
        if "peerAsn" in details or "peerState" in details:
            peer_as = details.get("peerAsn", "N/A")
            state = details.get("peerState", "N/A")
            desc = details.get("description", "N/A")  # если есть
            det_str = f"AS{peer_as}, {state}, {desc}"
        # Juniper формат
        elif "peer-as" in details or "peer-state" in details or "description" in details:
            def get_data(field):
                val = details.get(field, [{}])
                if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                    return val[0].get("data", "N/A")
                elif isinstance(val, str):
                    return val
                else:
                    return "N/A"
            peer_as = get_data("peer-as")
            state = get_data("peer-state")
            desc = get_data("description")
            det_str = f"AS{peer_as}, {state}, {desc}"

    elif isinstance(details, str):
        det_str = details

    return det_str

def write_reports(policies: List[Dict], incidents: List[Dict], config: Config, bgp_stats: Dict):
    # --- CSV ---
    with open(config.report_csv, "w", newline="", encoding="utf-8") as cf:
        fieldnames = ["router", "peer", "issue", "remote_as", "expected_as", "afi", "state", "details"]
        w = csv.DictWriter(cf, fieldnames=fieldnames)
        w.writeheader()
        for inc in incidents:
            w.writerow({
                "router": inc.get("router"),
                "peer": inc.get("peer"),
                "issue": inc.get("issue"),
                "remote_as": inc.get("remote_as"),
                "expected_as": inc.get("expected_as"),
                "afi": inc.get("afi"),
                "state": inc.get("state"),
                "details": _format_details(inc.get("details"))
            })

    # --- Markdown ---
    with open(config.report_md, "w", encoding="utf-8") as md:
        md.write("# BGP Policy Check Report\n\n")
        md.write("## Summary\n\n")
        md.write(f"- Total policy peers parsed: {len([p for p in policies if p.get('peer_ip')])}\n")
        md.write(f"- Total incidents found: {len(incidents)}\n\n")
        md.write("## BGP Sessions Summary\n\n")

        afi_stats = bgp_stats["afi"]
        for afi, data in afi_stats.items():
            total = data["total"]
            if total > 0:
                md.write(f"### {afi.upper()}\n")
                states = data["states"]
                for state, sdata in states.items():
                    st_total = sdata["total"]
                    if st_total > 0:
                        with_policy = sdata["with_policy"]
                        without_policy = sdata["without_policy"]
                        md.write(f"- {state}: {st_total} ({without_policy}/{with_policy})\n")
                md.write(f"- Total {afi.upper()}: {total}\n\n")

        md.write(f"- Total sessions: {bgp_stats['total']}\n")
        if bgp_stats["other"] > 0:
            md.write(f"- Other (no AFI match): {bgp_stats['other']}\n")

        md.write("\n## Incidents\n\n")
        for inc in incidents:
            md.write(f"- Router: **{inc.get('router')}**; Peer: `{inc.get('peer')}`; Issue: **{inc.get('issue')}**; ")
            if inc.get("remote_as"):
                md.write(f"remote_as: `{inc.get('remote_as')}`; ")
            if inc.get("expected_as"):
                md.write(f"expected_as: `{inc.get('expected_as')}`; ")
            if inc.get("afi"):
                md.write(f"afi: `{inc.get('afi')}`; ")
            if inc.get("state"):
                md.write(f"state: `{inc.get('state')}`; ")
            if inc.get("details"):
                md.write(f"details: `{_format_details(inc.get('details'))[:200].replace('`','')}`")
            md.write("\n\n")

        md.write("\n\n## Notes\n\n")
        md.write("- ASNs in range 64512–65534 и AS65500 были исключены как приватные.\n")
        md.write("- Адреса с сетевыми (.0) или broadcast (.255) помечены как подозрительные при известном CIDR.\n")
        md.write("- Если netmiko не установлен, SSH-проверка не выполняется.\n")

    print(f"Reports written: {config.report_csv}, {config.report_md}")

    # --- JSON ---
    if config.json_report and config.report_json:
        enriched_incidents = []
        for inc in incidents:
            enriched = inc.copy()
            enriched["details"] = _format_details(inc.get("details"))
            enriched_incidents.append(enriched)

        # Фильтруем AFI в summary под выбранный фильтр (ipv4/ipv6/all)
        afi_stats = bgp_stats["afi"]
        if config.afi_filter in ("ipv4", "ipv6"):
            afi_stats = {config.afi_filter: afi_stats[config.afi_filter]}

        data = {
            "summary": {
                "total_policy_peers": len([p for p in policies if p.get("peer_ip")]),
                "total_incidents": len(incidents)
            },
            "bgp_sessions_summary": {
                "afi": afi_stats,
                "total_sessions": bgp_stats["total"],
                "other_sessions": bgp_stats["other"]
            },
            "incidents": enriched_incidents,
            "notes": [
                "ASNs in range 64512–65534 и AS65500 были исключены как приватные.",
                "Адреса с сетевыми (.0) или broadcast (.255) помечены как подозрительные при известном CIDR.",
                "Если netmiko не установлен, SSH-проверка не выполняется."
            ]
        }
        with open(config.report_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"JSON report written: {config.report_json}")

    # --- YAML ---
    if config.yaml_report and config.report_yaml:
        if yaml is None:
            print("PyYAML is not installed; skipping YAML report.")
        else:
            write_yaml_report(policies, incidents, config, bgp_stats)
            print(f"YAML report written: {config.report_yaml}")
