from typing import Dict

from contracts_mailer import EmailContracts
from pyobas._injectors.injector_helper import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASEmail:
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
                "injector_contracts": {"data": EmailContracts.build_contract()},
            },
        )
        self.helper = OpenBASInjectorHelper(self.config)

    def _process_message(self, data: Dict) -> str:
        print(data)
        return "OK"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    openBASEmail = OpenBASEmail()
    openBASEmail.start()
