import json
import re
import subprocess
import time
from typing import Dict

from contracts_nuclei import (
    CLOUD_SCAN_CONTRACT,
    CVE_SCAN_CONTRACT,
    EXPOSURE_SCAN_CONTRACT,
    HTTP_SCAN_CONTRACT,
    MISCONFIG_SCAN_CONTRACT,
    PANEL_SCAN_CONTRACT,
    TEMPLATE_SCAN_CONTRACT,
    WORDPRESS_SCAN_CONTRACT,
    XSS_SCAN_CONTRACT,
    NucleiContracts,
)
from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASNuclei:
    def __init__(self):
        self.config = OpenBASConfigHelper(
            __file__,
            {
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openbas_nuclei",
                },
                "injector_contracts": {"data": NucleiContracts.build_contracts()},
            },
        )
        self.helper = OpenBASInjectorHelper(self.config, open("img/nuclei.jpg", "rb"))

    def nuclei_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        nuclei_args = ["nuclei"]
        content = data["injection"]["inject_content"]
        added_j = False
        tag_map = {
            CLOUD_SCAN_CONTRACT: "cloud",
            MISCONFIG_SCAN_CONTRACT: "misconfiguration",
            EXPOSURE_SCAN_CONTRACT: "exposure",
            PANEL_SCAN_CONTRACT: "panel",
            XSS_SCAN_CONTRACT: "xss",
            WORDPRESS_SCAN_CONTRACT: "wordpress",
            HTTP_SCAN_CONTRACT: "http",
        }
        is_manual = content.get("target_selector") == "manual"
        has_no_template = not (content.get("template") or content.get("template_path"))
        if is_manual and has_no_template and contract_id in tag_map:
            nuclei_args += ["-t", "/"]
        if contract_id == CVE_SCAN_CONTRACT:
            nuclei_args += ["-tags", "cve"]
            nuclei_args += ["-j"]
            added_j = True
        else:
            if contract_id in tag_map:
                nuclei_args += ["-tags", tag_map[contract_id]]
            elif contract_id == TEMPLATE_SCAN_CONTRACT:
                # On ajoute -t "/" seulement si aucun template n'est spécifié dans le contenu
                if not (content.get("template") or content.get("template_path")):
                    nuclei_args += ["-t", "/"]
            else:
                raise ValueError("Unknown contract ID")

        # Ajout du template si précisé
        if content.get("template"):
            nuclei_args += ["-t", content["template"]]
            if "cve" in content["template"].lower() and not added_j:
                nuclei_args += ["-j"]
                added_j = True

        elif content.get("template_path"):
            nuclei_args += ["-t", content["template_path"]]
            if "cve" in content["template_path"].lower() and not added_j:
                nuclei_args += ["-j"]
                added_j = True
        targets = []
        # Gestion des cibles : assets ou targets définis dans l'injection
        if data["injection"]["inject_content"]["target_selector"] == "assets":
            selector = data["injection"]["inject_content"]["target_property_selector"]
            for asset in data["assets"]:
                if selector == "seen_ip":
                    targets.append(asset["endpoint_seen_ip"])
                elif selector == "local_ip":
                    if not asset["endpoint_ips"]:
                        raise ValueError("No IP found for this endpoint")
                    targets.append(asset["endpoint_ips"][0])
                else:
                    targets.append(asset["endpoint_hostname"])
        else:
            targets = [
                t.strip()
                for t in data["injection"]["inject_content"]["targets"].split(",")
            ]
        targets = self.get_targets(data)
        for target in targets:
            nuclei_args += ["-u", target]

        input_data = "\n".join(targets).encode("utf-8")

        self.helper.injector_logger.info(
            "Executing nuclei with: " + " ".join(nuclei_args)
        )
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": " ".join(nuclei_args),
                "execution_status": "INFO",
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )
        result = subprocess.run(
            nuclei_args, input=input_data, capture_output=True, check=True
        )
        lines = result.stdout.decode("utf-8").splitlines()
        findings = []
        others = []
        for line in lines:
            try:
                j = json.loads(line)
                if j.get(
                    "matcher-status"
                ):  # Vérifier que le statut de la correspondance est "true"
                    cve_ids = (
                        j.get("info", {})
                        .get("classification", {})
                        .get("cve-id", ["Unknown CVE"])
                    )
                    severity = j.get("info", {}).get(
                        "severity", "Unknown Severity"
                    )  # Extraire la sévérité
                    host = j.get("host", j.get("url", ""))  # Extraire l'hôte ou l'URL
                    if isinstance(cve_ids, list):
                        cve_str = ", ".join(c.upper() for c in cve_ids)
                    else:
                        cve_str = f"{cve_ids.upper()}"
                    finding = {
                        "severity": severity,
                        "host": host,
                        "id": cve_str,
                    }
                    if not any(
                        f["host"] == finding["host"]
                        and f["id"] == finding["id"]
                        and f["severity"] == finding["severity"]
                        for f in findings
                    ):
                        self.helper.injector_logger.info(
                            "New finding: " + " ".join(finding)
                        )
                        findings.append(finding)

            except json.JSONDecodeError:
                self.helper.injector_logger.debug(f"Line added to others: {line}")
                if line.strip():  # Ajoute uniquement si la ligne n'est pas vide
                    clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
                    others.append(clean_line)
        message_parts = []
        if findings:
            message_parts.append(f"{len(findings)} CVE(S)")
        if others:
            message_parts.append(f"{len(others)} Vulnerabilitie(s)")
        if not findings and not others:
            message_parts.append("Good News: Nothing Found !")
        return {
            "message": "Nuclei completed: " + " ".join(message_parts),
            "outputs": {"cve": findings, "others": others},
        }

    def get_targets(self, data: Dict):
        targets = []
        content = data["injection"]["inject_content"]
        if content["target_selector"] == "assets" and data.get("assets"):
            selector = content["target_property_selector"]
            for asset in data["assets"]:
                if selector == "seen_ip":
                    targets.append(asset["endpoint_seen_ip"])
                elif selector == "local_ip":
                    if not asset["endpoint_ips"]:
                        raise ValueError("No IP found for this endpoint")
                    targets.append(asset["endpoint_ips"][0])
                else:
                    targets.append(asset["endpoint_hostname"])
        elif content["target_selector"] == "manual":
            targets = [t.strip() for t in content["targets"].split(",") if t.strip()]
        else:
            raise ValueError("No targets provided for this injection")
        return targets

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data=reception_data
        )
        # Execute inject
        try:
            execution_result = self.nuclei_execution(start, data)
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_output_structured": json.dumps(execution_result["outputs"]),
                "execution_status": "SUCCESS",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenBASNuclei().start()
