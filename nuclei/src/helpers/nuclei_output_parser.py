import json
import re
from typing import Dict


class NucleiOutputParser:
    def parse(self, stdout: str) -> Dict:
        findings, others = [], []
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
                        findings.append(
                            {"severity": severity, "host": host, "id": cve_str}
                        )
                        seen.add(key)
            except json.JSONDecodeError:
                clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
                if clean_line.strip():
                    others.append(clean_line)

        message_parts = []
        if findings:
            message_parts.append(f"{len(findings)} CVE(S)")
        if others:
            message_parts.append(f"{len(others)} Vulnerabilities(s)")
        if not findings and not others:
            message_parts.append("Good News: Nothing Found !")

        return {
            "message": "Nuclei completed: " + " ".join(message_parts),
            "outputs": {"cve": findings, "others": others},
        }
