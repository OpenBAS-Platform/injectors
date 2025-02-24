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
)

TYPE = "openbas_nmap"
TCP_SYN_SCAN_CONTRACT = "5948c96c-4064-4c0d-b079-51ec33f31b91"
TCP_CONNECT_SCAN_CONTRACT = "bb503f7c-1f17-49e1-ac31-f4c2e99fd704"


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
        targets = ContractAsset(
            cardinality=ContractCardinality.Multiple,
            key="targets",
            label="Targeted assets",
            defaultValue=None,
            mandatory=True,
        )
        # Output
        output = ContractOutputElement(
            type=ContractOutputType.Port,
            field="ports",
            isMultiple=True,
            labels=["scan"],
        )
        # Post contract raw
        nmap_contract_fields: List[ContractElement] = (
            ContractBuilder().add_fields([targets]).build_fields()
        )
        nmap_contract_outputs: List[ContractOutputElement] = (
            ContractBuilder().add_outputs([output]).build_outputs()
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
        return prepare_contracts([syn_scan_contract, tcp_scan_contract])
