import json
import subprocess
import time
from typing import Dict

from netexec.helpers.mapper import Mapper
from netexec.helpers.netexec_command_builder import NetExecCommandBuilder
from netexec.helpers.netexec_process import NetExecProcess
from netexec.netexec_contracts.netexec_constants import TYPE
from netexec.netexec_contracts.netexec_contracts import NetExecContracts
from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASNetExec:
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
                    "default": TYPE,
                },
                "injector_contracts": {"data": NetExecContracts.build_contracts()},
            },
        )
        # TODO: add img
        self.helper = OpenBASInjectorHelper(
            self.config, open("netexec/img/netexec.jpg", "rb")
        )

        if not self._check_netexec_installed():
            raise RuntimeError(
                "NetExec is not installed or is not accessible from your PATH."
            )

    def _check_netexec_installed(self):
        try:
            NetExecProcess.net_exec_execute()
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def netexec_execution(self, start: float, data: Dict) -> Dict:
        inject_id = Mapper.get_inject_id(data)
        contract_id = Mapper.get_contract_id(data)
        content = Mapper.get_content(data)

        netexec_args = NetExecCommandBuilder.build_args(contract_id, content)

        self.helper.injector_logger.info(
            "Executing NetExec with: " + " ".join(netexec_args)
        )
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": " ".join(netexec_args),
                "execution_status": "INFO",
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )

        result = NetExecProcess.net_exec_execute(netexec_args)
        # TODO: add parser on next step
        return result.stdout.decode("utf-8")

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = Mapper.get_inject_id(data)

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(inject_id, reception_data)

        # Execute inject
        # TODO: should have SUCCESS, complete at global constant
        try:
            result = self.netexec_execution(start, data)
            callback_data = {
                "execution_message": result["message"],
                "execution_output_structured": json.dumps(result["outputs"]),
                "execution_status": "SUCCESS",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(inject_id, callback_data)
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(inject_id, callback_data)

    def start(self):
        self.helper.listen(message_callback=self.process_message)

if __name__ == "__main__":
    OpenBASNetExec().start()
