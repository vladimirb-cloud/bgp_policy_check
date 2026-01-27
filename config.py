import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    whois_file: Optional[str]
    routers_file: str
    output_dir: str
    rr_host: str
    as_number: str
    ssh_enabled: bool = True
    json_report: bool = False
    yaml_report: bool = False  # <-- Новое поле
    afi_filter: str = "all"
    vendor: str = "juniper_junos"
    exclude_private_asns: bool = True
    report_csv: Optional[str] = None
    report_md: Optional[str] = None
    report_json: Optional[str] = None
    report_yaml: Optional[str] = None  # <-- Новое поле
    cache_dir: Optional[str] = None

    def __post_init__(self):
        if self.report_csv is None:
            self.report_csv = os.path.join(self.output_dir, "report.csv")
        if self.report_md is None:
            self.report_md = os.path.join(self.output_dir, "report.md")
        if self.report_json is None and self.json_report:
            self.report_json = os.path.join(self.output_dir, "report.json")
        if self.report_yaml is None and self.yaml_report:
            self.report_yaml = os.path.join(self.output_dir, "report.yaml")
        if self.cache_dir is None:
            self.cache_dir = os.path.join(self.output_dir, "cache")
            os.makedirs(self.cache_dir, exist_ok=True)