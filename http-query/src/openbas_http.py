import time
from typing import Dict

import requests
from contracts_http import (
    HTTP_FORM_POST_CONTRACT,
    HTTP_FORM_PUT_CONTRACT,
    HTTP_GET_CONTRACT,
    HTTP_RAW_POST_CONTRACT,
    HTTP_RAW_PUT_CONTRACT,
    HttpContracts,
)
from pyobas._injectors.injector_helper import OpenBASConfigHelper, OpenBASInjectorHelper


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
                },
                "injector_contracts": {"data": HttpContracts.build_contract()},
            },
        )
        self.helper = OpenBASInjectorHelper(self.config)

    @staticmethod
    def http_execution(data: Dict):
        # Build headers
        inject_headers = data["injection"]["inject_content"].get("headers", [])
        headers = {}
        for header_definition in inject_headers:
            headers[header_definition["key"]] = header_definition["value"]
        # Build http session
        session = requests.Session()
        is_basic_auth = data["injection"]["inject_content"]["basicAuth"]
        if is_basic_auth:
            user = data["injection"]["inject_content"]["basicUser"]
            password = data["injection"]["inject_content"]["basicPassword"]
            session.auth = (user, password)
        # Contract execution
        inject_contract = data["injection"]["inject_contract"]
        # Get
        if inject_contract == HTTP_GET_CONTRACT:
            url = data["injection"]["inject_content"]["uri"]
            response = session.get(url=url, headers=headers)
            success = 200 <= response.status_code < 300
            success_status = "SUCCESS" if success else "ERROR"
            return {
                "response": response.text,
                "status": success_status,
                "code": response.status_code,
                "message": "Get execution for " + url,
            }
        # Post
        if inject_contract == HTTP_RAW_POST_CONTRACT:
            raise Exception("TO_BE_IMPLEMENTED")
        # Put
        if inject_contract == HTTP_RAW_PUT_CONTRACT:
            raise Exception("TO_BE_IMPLEMENTED")
        # Form Post
        if inject_contract == HTTP_FORM_POST_CONTRACT:
            raise Exception("TO_BE_IMPLEMENTED")
        # Form Put
        if inject_contract == HTTP_FORM_PUT_CONTRACT:
            raise Exception("TO_BE_IMPLEMENTED")
        # Nothing supported
        raise Exception("UNSUPPORTED_CONTRACT")

    def _process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data=reception_data
        )
        # Execute inject
        try:
            execution_result = self.http_execution(data)
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
                "execution_message": "Execution failure because of " + str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_context_identifiers": None,
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
            print(e)

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    openBASEmail = OpenBASHttp()
    openBASEmail.start()
