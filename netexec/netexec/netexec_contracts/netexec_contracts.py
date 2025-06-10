from typing import List

from netexec.netexec_contracts.netexec_constants import (
    TYPE, IP_FIELD_KEY,
    USER_FIELD_KEY, PASSWORD_FIELD_KEY, MODULE_FIELD_KEY,
    SMB_SCAN_VULN_CONTRACT
)

from pyobas.contracts.contract_config import SupportedLanguage
from pyobas.contracts import ContractBuilder
from pyobas.contracts.contract_config import ContractConfig, ContractSelect, ContractElement, Contract, \
    prepare_contracts


class NetExecContracts:

    @staticmethod
    def build_contracts():
        # -- CONFIG --
        contract_config = ContractConfig(
            type=TYPE,
            # TODO: check validity of name
            label={
                SupportedLanguage.en: "NetExec",
                SupportedLanguage.fr: "NetExec",
            },
            # TODO: change color if necessary
            color_dark="#ff5722",
            color_light="#ff5722",
            expose=True,
        )

        # SMB
        ip_field = ContractSelect(
            key=IP_FIELD_KEY,
            label="IP",
            mandatory=True,
        )
        user_field = ContractSelect(
            key=USER_FIELD_KEY,
            label="User",
            mandatory=True,
        )
        password_field = ContractSelect(
            key=PASSWORD_FIELD_KEY,
            label="Password",
            mandatory=True,
        )
        module_field = ContractSelect(
            key=MODULE_FIELD_KEY,
            label="Module",
            mandatory=True,
        )
        smb_fields = [ip_field, user_field, password_field, module_field]
        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(smb_fields)
            .build_fields()
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
                manual=False,
                outputs=[]
            )

        # TODO: create a contract by protocol
        return prepare_contracts(
            [
                build_contract(SMB_SCAN_VULN_CONTRACT, "NetExec - SMB", "NetExec - SMB")
            ]
        )
