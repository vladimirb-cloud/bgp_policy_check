import csv
import json
import yaml  # <-- Добавим
from typing import List, Dict
from ..config import Config

def write_yaml_report(policies: List[Dict], incidents: List[Dict], config: Config, bgp_stats: Dict):
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
            "ASNs in range 64512–65534 and AS65500 were excluded as private/internal.",
            "Addresses that appear to be network (.0) or broadcast (.255) were marked as suspicious when CIDR is known.",
            "Если netmiko не установлен, SSH-проверка не выполнится."
        ]
    }
    with open(config.report_yaml, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def write_reports(policies: List[Dict], incidents: List[Dict], config: Config, bgp_stats: Dict):
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
                "details": inc.get("details")
            })

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
                det = inc.get("details")
                # Попробуем красиво распарсить raw-данные Junos
                if isinstance(det, dict):
                    peer_as = det.get("peer-as", [{}])[0].get("data", "N/A")
                    state = det.get("peer-state", [{}])[0].get("data", "N/A")
                    desc = det.get("description", [{}])[0].get("data", "N/A")
                    det_str = f"AS{peer_as}, {state}, {desc}"
                else:
                    det_str = str(det)
                md.write(f"details: `{det_str[:200].replace('`','')}`")
            md.write("\n\n")
        md.write("\n\n## Notes\n\n")
        md.write("- ASNs in range 64512–65534 and AS65500 were excluded as private/internal.\n")
        md.write("- Addresses that appear to be network (.0) or broadcast (.255) were marked as suspicious when CIDR is known.\n")
        md.write("- Если netmiko не установлен, SSH-проверка не выполнится.\n")

    print(f"Reports written: {config.report_csv}, {config.report_md}")
    if config.json_report and config.report_json:
        write_json_report(policies, incidents, config, bgp_stats)
        print(f"JSON report written: {config.report_json}")
    if config.yaml_report and config.report_yaml:
        write_yaml_report(policies, incidents, config, bgp_stats)
        print(f"YAML report written: {config.report_yaml}")

def write_json_report(policies: List[Dict], incidents: List[Dict], config: Config, bgp_stats: Dict):
    # Обогатим инциденты для JSON
    enriched_incidents = []
    for inc in incidents:
        enriched = inc.copy()
        details = inc.get("details")
        if isinstance(details, dict):
            peer_as = details.get("peer-as", [{}])[0].get("data", "N/A")
            state = details.get("peer-state", [{}])[0].get("data", "N/A")
            desc = details.get("description", [{}])[0].get("data", "N/A")
            enriched["details"] = f"AS{peer_as}, {state}, {desc}"
        enriched_incidents.append(enriched)

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
        "incidents": enriched_incidents,
        "notes": [
            "ASNs in range 64512–65534 and AS65500 were excluded as private/internal.",
            "Addresses that appear to be network (.0) or broadcast (.255) were marked as suspicious when CIDR is known.",
            "Если netmiko не установлен, SSH-проверка не выполнится."
        ]
    }
    with open(config.report_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)