from typing import List, Dict

from netexec.netexec_contracts.netexec_constants import PROTOCOL_SMB, SMB_SCAN_VULN_CONTRACT, USER_FIELD_KEY, PASSWORD_FIELD_KEY, \
    MODULE_FIELD_KEY, IP_FIELD_KEY


class NetExecCommandBuilder:

    @staticmethod
    def build_args(contract_id: str, content: Dict) -> List[str]:
        args = ["nxc"]

        if contract_id == SMB_SCAN_VULN_CONTRACT:
            args += [PROTOCOL_SMB]
            args += [content.get(IP_FIELD_KEY)]
            args += ["-u", content.get(USER_FIELD_KEY)]
            args += ["-p", content.get(PASSWORD_FIELD_KEY)]
            args += ["-M", content.get(MODULE_FIELD_KEY)]

        return args
