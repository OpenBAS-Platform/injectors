import json
import re
from collections import defaultdict
from typing import Dict

class NucleiOutputParser:
    def parse(self, stdout: str, ip_to_asset_id_map: dict) -> Dict:
        raw_findings = []
        others = []
        seen = set()

        for line in stdout.splitlines():
            try:
                j = json.loads(line)
                if j.get("matcher-status"):
                    cve_ids = (
                        j.get("info", {})
                        .get("classification", {})
                        .get("cve-id", ["Unknown CVE"])
                    )
                    severity = j.get("info", {}).get("severity", "Unknown Severity")
                    host = j.get("host", j.get("url", ""))
                    cve_str = (
                        ", ".join(c.upper() for c in cve_ids)
                        if isinstance(cve_ids, list)
                        else cve_ids.upper()
                    )
                    key = (host, cve_str, severity)
                    if key not in seen:
                        raw_findings.append(
                            {
                                "severity": severity,
                                "host": host,
                                "id": cve_str,
                                "asset_id": ip_to_asset_id_map.get(host, ""),
                            }
                        )
                        seen.add(key)
            except json.JSONDecodeError:
                clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
                if clean_line.strip():
                    others.append(clean_line)

        # Group by ID
        grouped = defaultdict(lambda: {"asset_ids": set(), "hosts": set(), "severity": None})
        for finding in raw_findings:
            fid = finding["id"]
            grouped[fid]["asset_ids"].add(finding["asset_id"])
            grouped[fid]["hosts"].add(finding["host"])
            grouped[fid]["severity"] = finding["severity"]

        grouped_findings = [
            {
                "id": fid,
                "asset_ids": sorted(list(data["asset_ids"])),
                "hosts": sorted(list(data["hosts"])),
                "severity": data["severity"],
            }
            for fid, data in grouped.items()
        ]

        message_parts = []
        if grouped_findings:
            message_parts.append(f"{len(grouped_findings)} CVE(S)")
        if others:
            message_parts.append(f"{len(others)} Vulnerabilities(s)")
        if not grouped_findings and not others:
            message_parts.append("Good News: Nothing Found !")

        return {
            "message": "Nuclei completed: " + " ".join(message_parts),
            "outputs": {"cve": grouped_findings, "others": others},
        }
