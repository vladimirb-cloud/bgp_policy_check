import argparse
import os
import logging
from .config import Config
from .parsers.whois_parser import fetch_and_parse_whois
from .comparators.bgp_comparator import compare_policies_to_routers
from .reporters.report_generator import write_reports

def setup_logging(output_dir: str):
    log_path = os.path.join(output_dir, "bgp_policy_check.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(log_path, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

def main():
    parser = argparse.ArgumentParser(description="BGP Policy Checker")
    parser.add_argument("--as-number", default="12345", help="AS number to fetch policy from RR (default: 12345)")
    parser.add_argument("--routers", default="bgp_policy_check/router.csv", help="Path to routers.csv (default: bgp_policy_check/router.csv)")
    parser.add_argument("--output-dir", default="bgp_policy_check/reports", help="Output directory for reports and logs (default: bgp_policy_check/reports)")
    parser.add_argument("--rr-host", default="rr.ntt.net", help="Route server host to query (default: rr.ntt.net)")
    parser.add_argument("--json-report", action="store_true", help="Also output report in JSON format")
    parser.add_argument("--yaml-report", action="store_true", help="Also output report in YAML format")
    parser.add_argument("--no-ssh", action="store_true", help="Do not connect to routers; only parse RR policy")
    parser.add_argument("--afi", choices=["ipv4", "ipv6", "all"], default="all", help="Filter by AFI: ipv4, ipv6, or all (default: all)")
    args = parser.parse_args()

    config = Config(
        whois_file=None,
        routers_file=args.routers,
        output_dir=args.output_dir,
        rr_host=args.rr_host,
        as_number=args.as_number,
        ssh_enabled=not args.no_ssh,
        json_report=args.json_report,
        yaml_report=args.yaml_report,
        afi_filter=args.afi
    )

    os.makedirs(config.output_dir, exist_ok=True)

    setup_logging(config.output_dir)

    logger = logging.getLogger(__name__)

    logger.info(f"Starting BGP policy check for AS{config.as_number} from {config.rr_host}, AFI filter: {config.afi_filter}")

    print("Fetching policy from RR...")
    policies = fetch_and_parse_whois(config.as_number, config.rr_host, config)
    logger.info(f"Parsed {len(policies)} policy entries (after filtering privates).")

    routers = read_routers_csv(config.routers_file)
    logger.info(f"Loaded {len(routers)} routers from {config.routers_file}")

    incidents, bgp_stats = compare_policies_to_routers(policies, routers, config)

    write_reports(policies, incidents, config, bgp_stats)

    logger.info("Done.")
    print("Done.")

def read_routers_csv(path: str) -> list:
    import csv
    routers = []
    with open(path, newline="", encoding="utf-8") as cf:
        r = csv.DictReader(cf)
        for row in r:
            routers.append(row)
    return routers

if __name__ == "__main__":
    main()