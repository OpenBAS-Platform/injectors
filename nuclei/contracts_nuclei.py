from typing import List
from pyobas.contracts import ContractBuilder
from pyobas.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractText,
    SupportedLanguage,
    prepare_contracts,
)

TYPE = "openbas_nuclei"
CLOUD_SCAN_CONTRACT = "c01fa03a-ea7e-43a3-9b1a-44b2f41a8c5f"
MISCONFIG_SCAN_CONTRACT = "a4eb02bd-3c9f-4a97-b9a1-54a9b7a7f21e"
EXPOSURE_SCAN_CONTRACT = "9c4b2f29-61f6-4ae3-80e7-928fe4a2fc0b"
PANEL_SCAN_CONTRACT = "3cf1b7a6-39d2-4531-8c8e-2b7c67470d1e"
XSS_SCAN_CONTRACT = "2e7fc079-9ebf-4adf-8d94-79d8f7bb32f4"
WORDPRESS_SCAN_CONTRACT = "2e7fc079-4531-4444-4444-44b2f41a8c5f"
HTTP_SCAN_CONTRACT = "2e7fc079-4444-4531-4444-2b7c67470d1e"
TEMPLATE_SCAN_CONTRACT = "2e7fc079-4531-4444-4444-928fe4a2fc0b"
CVE_SCAN_CONTRACT = "2e7fc079-4444-4531-4444-928fe4a1fc0b"


class NucleiContracts:

    @staticmethod
    def build_contracts():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Nuclei Scan",
                SupportedLanguage.fr: "Nuclei Scan",
            },
            color_dark="#ff5722",
            color_light="#ff5722",
            expose=True,
        )

        target_selector = ContractSelect(
            key="target_selector",
            label="Type of targets",
            defaultValue=["assets"],
            mandatory=True,
            mandatoryGroups=["assets", "targets"],
            choices={"assets": "Assets", "manual": "Manual"},
        )
        targets_assets = ContractAsset(
            cardinality=ContractCardinality.Multiple,
            key="assets",
            label="Targeted assets",
            mandatory=False,
            linkedFields=[target_selector],
            linkedValues=["assets"],
        )
        target_property_selector = ContractSelect(
            key="target_property_selector",
            label="Targeted property",
            defaultValue=["hostname"],
            mandatory=False,
            linkedFields=[target_selector],
            linkedValues=["assets"],
            choices={
                "hostname": "Hostname",
                "seen_ip": "Seen IP",
                "local_ip": "Local IP (first)",
            },
        )
        targets_manual = ContractText(
            key="targets",
            label="Manual targets (comma-separated)",
            mandatory=False,
            mandatoryConditionField="target_selector",
            mandatoryConditionValue="manual",
            linkedFields=[target_selector],
            linkedValues=["manual"],
        )
        template_manual = ContractText(
            key="template",
            label="Template to use (-t)",
            mandatory=False,
            linkedFields=[target_selector],
            linkedValues=["manual"],
        )
        output_vulns = ContractOutputElement(
            type=ContractOutputType.CVE,
            field="cve",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["nuclei"],
        )
        output_others = ContractOutputElement(
            type=ContractOutputType.Text,
            field="others",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["nuclei"],
        )
        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields([
                target_selector,
                targets_assets,
                target_property_selector,
                targets_manual,
				template_manual,
            ])
            .build_fields()
        )
        nuclei_contract_outputs: List[ContractOutputElement] = (
            ContractBuilder().add_outputs([output_vulns, output_others]).build_outputs()
        )

        def build_contract(contract_id, label_en, label_fr):
            return Contract(
                contract_id=contract_id,
                config=contract_config,
                label={
                    SupportedLanguage.en: label_en,
                    SupportedLanguage.fr: label_fr,
                },
                fields=fields,
                outputs=nuclei_contract_outputs,
                manual=False,
            )

        return prepare_contracts([
            build_contract(CLOUD_SCAN_CONTRACT, "Nuclei - Cloud Templates", "Nuclei - Cloud Templates"),
            build_contract(MISCONFIG_SCAN_CONTRACT, "Nuclei - Misconfigurations Templates", "Nuclei - Misconfigurations Templates"),
            build_contract(EXPOSURE_SCAN_CONTRACT, "Nuclei - Exposures Templates", "Nuclei - Expositions Templates"),
            build_contract(CVE_SCAN_CONTRACT, "Nuclei - CVE Templates", "Nuclei - CVE Templates"),
            build_contract(PANEL_SCAN_CONTRACT, "Nuclei - Panel Templates", "Nuclei - Panel Templates"),
            build_contract(XSS_SCAN_CONTRACT, "Nuclei - XSS Templates", "Nuclei - XSS Templates"),
            build_contract(WORDPRESS_SCAN_CONTRACT, "Nuclei - Wordpress Templates", "Nuclei - Wordpress Templates"),
            build_contract(TEMPLATE_SCAN_CONTRACT, "Nuclei - Manual Templates", "Nuclei - Manual Templates"),
        ])