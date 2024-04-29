from typing import List

from pyobas.contracts import ContractBuilder
from pyobas.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractAssetGroup,
    ContractAttachment,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractTextArea,
    SupportedLanguage,
    prepare_contracts,
)

TYPE = "openbas_tanium"
COMMAND_LINE_WINDOWS_CONTRACT = "9cecb9d0-3c90-4497-a063-bd5611e5c10d"
COMMAND_LINE_LINUX_CONTRACT = "825bfd90-0602-4dba-be2d-126101a06c79"
EXECUTE_FILE_WINDOWS = "362ca841-8fa7-47a3-8c49-f061abc96b01"
EXECUTE_FILE_LINUX = "4133f5a4-3b0a-405c-b011-fbbe4d64cdc4"


class TaniumContracts:

    @staticmethod
    def build_contract():
        # Config
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Tanium Execution",
                SupportedLanguage.fr: "Exécution Tanium",
            },
            color_dark="#00bcd4",
            color_light="#00bcd4",
            expose=True,
        )
        command_line_windows_instance: List[ContractElement] = (
            ContractBuilder()
            .optional(
                ContractAsset(
                    key="asset",
                    label="Asset",
                    mandatory=True,
                    cardinality=ContractCardinality.Multiple,
                )
            )
            .optional(
                ContractAssetGroup(
                    key="asset_group",
                    label="Asset group",
                    mandatory=True,
                    cardinality=ContractCardinality.Multiple,
                )
            )
            .mandatory(
                ContractTextArea(
                    key="command_line", label="Command line", mandatory=True
                )
            )
            .build()
        )
        command_line_windows_contract = Contract(
            contract_id=COMMAND_LINE_WINDOWS_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Execute command line (Windows)",
                SupportedLanguage.fr: "Exécuter une ligne de commande (Windows)",
            },
            fields=command_line_windows_instance,
            manual=False,
            platforms=["Windows"],
        )
        command_line_linux_instance: List[ContractElement] = (
            ContractBuilder()
            .optional(
                ContractAsset(
                    key="asset",
                    label="Asset",
                    mandatory=True,
                    cardinality=ContractCardinality.Multiple,
                )
            )
            .optional(
                ContractAssetGroup(
                    key="asset_group",
                    label="Asset group",
                    mandatory=True,
                    cardinality=ContractCardinality.Multiple,
                )
            )
            .mandatory(
                ContractTextArea(
                    key="command_line", label="Command line", mandatory=True
                )
            )
            .build()
        )
        command_line_linux_contract = Contract(
            contract_id=COMMAND_LINE_LINUX_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Execute command line (Linux)",
                SupportedLanguage.fr: "Exécuter une ligne de commande (Linux)",
            },
            fields=command_line_linux_instance,
            manual=False,
            platforms=["Linux"],
        )
        execute_file_windows_instance: List[ContractElement] = (
            ContractBuilder()
            .optional(
                ContractAsset(
                    key="asset",
                    label="Asset",
                    mandatory=True,
                    cardinality=ContractCardinality.Multiple,
                )
            )
            .optional(
                ContractAssetGroup(
                    key="asset_group",
                    label="Asset group",
                    mandatory=True,
                    cardinality=ContractCardinality.Multiple,
                )
            )
            .mandatory(
                ContractTextArea(
                    key="command_line", label="Command line", mandatory=True
                )
            )
            .mandatory(ContractAttachment(key="file", label="File", mandatory=True))
            .build()
        )
        execute_file_windows_contract = Contract(
            contract_id=EXECUTE_FILE_WINDOWS,
            config=contract_config,
            label={
                SupportedLanguage.en: "Execute a file (Windows)",
                SupportedLanguage.fr: "Exécuter un fichier (Windows)",
            },
            fields=execute_file_windows_instance,
            manual=False,
            platforms=["Windows"],
        )
        return prepare_contracts(
            [
                command_line_windows_contract,
                command_line_linux_contract,
                execute_file_windows_contract,
            ]
        )
