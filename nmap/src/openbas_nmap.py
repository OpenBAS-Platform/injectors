import time
import json
import subprocess
from typing import Dict

import requests
from contracts_nmap import (
    TCP_CONNECT_SCAN_CONTRACT,
    TCP_SYN_SCAN_CONTRACT,
    NmapContracts,
)
from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASHttp:
    def __init__(self):
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                # Config information
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openbas_nmap",
                },
                "injector_contracts": {"data": NmapContracts.build_contract()},
            },
        )
        self.helper = OpenBASInjectorHelper(
            self.config, open("img/icon-nmap.png", "rb")
        )

    def nmap_execution(self, data: Dict) -> Dict:
        nmap = subprocess.run(['nmap', '-Pn', '-sV', '-oX', '-', 'google.com'], check=True, capture_output=True)
        jc = subprocess.run(['jc', '--xml', '-p'], input=nmap.stdout, capture_output=True)


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
            execution_result = self.nmap_execution(data)
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_status": execution_result["status"],
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

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openBASHttp = OpenBASHttp()
    openBASHttp.start()
