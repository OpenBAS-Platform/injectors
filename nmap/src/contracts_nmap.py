from typing import List

from pyobas.contracts import ContractBuilder
from pyobas.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    SupportedLanguage,
    prepare_contracts,
    ContractOutput,
)
from pyobas.contracts.contract_config import ContractAsset

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
        output = (
            "url",
            "Text",
            # FIXME: it's an example
            ["reconnaissance phase"],
        )
        # Post contract raw
        nmap_contract_instance: List[ContractElement] = (
            ContractBuilder().add_fields([targets]).build()
        )
        syn_scan_contract = Contract(
            contract_id=TCP_SYN_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - SYN Scan",
                SupportedLanguage.fr: "Nmap - SYN Scan",
            },
            fields=nmap_contract_instance,
            manual=False,
        )
        tcp_scan_contract = Contract(
            contract_id=TCP_CONNECT_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - TCP Connect Scan",
                SupportedLanguage.fr: "Nmap - TCP Connect Scan",
            },
            fields=nmap_contract_instance,
            manual=False,
        )
        return prepare_contracts([syn_scan_contract, tcp_scan_contract])
