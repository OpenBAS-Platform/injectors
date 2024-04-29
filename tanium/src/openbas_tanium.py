import time
from typing import Dict

from contracts_tanium import TaniumContracts
from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASTanium:
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
                },
                "injector_contracts": {"data": TaniumContracts.build_contract()},
                "injector_custom_contracts": {"data": True},
                "injector_simulation_agent": {"data": True},
                "injector_simulation_agent_platforms": {
                    "data": ["Windows", "Linux", "MacOS"]
                },
            },
        )
        self.helper = OpenBASInjectorHelper(
            self.config, open("img/icon-tanium.png", "rb")
        )

    def attachments_to_files(self, request_data):
        documents = request_data["injection"].get("inject_documents", [])
        attachments = list(filter(lambda d: d["document_attached"] is True, documents))
        http_files = {}
        for attachment in attachments:
            response = self.helper.api.document.download(attachment["document_id"])
            if response.status_code == 200:
                http_files[attachment["document_name"]] = response.content
        return http_files

    def tanium_execution(self, data: Dict):
        # Find the asset by hostname or IP

        # If asset not found, report error

        # If asset found, launch the action
        # inject_contract = data["injection"]["inject_contract"]

        # Nothing supported
        return {
            "code": 400,
            "status": "ERROR",
            "message": "Selected contract is not supported",
        }

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
            execution_result = self.tanium_execution(data)
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_status": execution_result["status"],
                "execution_duration": int(time.time() - start),
                "execution_context_identifiers": None,
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_context_identifiers": None,
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openBASTanium = OpenBASTanium()
    openBASTanium.start()
