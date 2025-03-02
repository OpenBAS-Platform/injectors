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
    SupportedLanguage,
    prepare_contracts,
    ContractText,
    ContractSelect,
)

TYPE = "openbas_nmap"
TCP_SYN_SCAN_CONTRACT = "5948c96c-4064-4c0d-b079-51ec33f31b91"
TCP_CONNECT_SCAN_CONTRACT = "bb503f7c-1f17-49e1-ac31-f4c2e99fd704"
FIN_SCAN_CONTRACT = "ddc6387f-ba7f-498f-b383-0f568e1c6ae4"


class NmapContracts:

    @staticmethod
    def build_contract():
        # Config
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Nmap Scan",
                SupportedLanguage.fr: "Nmap Scan",
            },
            color_dark="#00bcd4",
            color_light="#00bcd4",
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
            mandatory=True,
            linkedFields=[target_selector],
            linkedValues=["assets"],
        )
        target_property_selector = ContractSelect(
            key="target_property_selector",
            label="Targeted property",
            defaultValue=["seen_ip"],
            mandatory=True,
            choices={
                "seen_ip": "Seen IP",
                "local_ip": "Local IP (first)",
                "hostname": "Hostname",
            },
            linkedFields=[target_selector],
            linkedValues=["assets"],
        )
        targets_manual = ContractText(
            key="targets",
            label="Targeted hostnames or IPs (separated by commas)",
            mandatory=False,
            mandatoryConditionField="target_selector",
            mandatoryConditionValue="manual",
            linkedFields=[target_selector],
            linkedValues=["manual"],
        )

        # Output
        output_ports_scans = ContractOutputElement(
            type=ContractOutputType.PortsScan,
            field="scan_results",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["scan"],
        )
        output_port = ContractOutputElement(
            type=ContractOutputType.Port,
            field="ports",
            isMultiple=True,
            isFindingCompatible=False,
            labels=["scan"],
        )
        # Post contract raw
        nmap_contract_fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    target_selector,
                    targets_assets,
                    target_property_selector,
                    targets_manual,
                ]
            )
            .build_fields()
        )
        nmap_contract_outputs: List[ContractOutputElement] = (
            ContractBuilder()
            .add_outputs([output_ports_scans, output_port])
            .build_outputs()
        )
        syn_scan_contract = Contract(
            contract_id=TCP_SYN_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - SYN Scan",
                SupportedLanguage.fr: "Nmap - SYN Scan",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
        )
        tcp_scan_contract = Contract(
            contract_id=TCP_CONNECT_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - TCP Connect Scan",
                SupportedLanguage.fr: "Nmap - TCP Connect Scan",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
        )
        fin_scan_contract = Contract(
            contract_id=FIN_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - FIN Scan",
                SupportedLanguage.fr: "Nmap - FIN Scan",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
        )
        return prepare_contracts(
            [syn_scan_contract, tcp_scan_contract, fin_scan_contract]
        )
