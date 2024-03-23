import json
from typing import Dict

from contracts_mailer import TYPE, EmailContracts
from pybas import OpenBAS
from pybas._injectors.injector_helper import OpenBASInjectorHelper
from pybas.utils import EnhancedJSONEncoder


class OpenBASEmail:
    def __init__(self):
        email_contract = EmailContracts.build_contract()
        email_json_contract = json.dumps(email_contract, cls=EnhancedJSONEncoder)
        config = {
            "injector_id": "ba0003bc-4edc-45f3-b047-bda6c3b66f74",
            "injector_name": "Mailer injector",
            "injector_type": TYPE,
            "injector_contracts": email_json_contract,
        }
        injector_config = {
            "connection": {
                "host": "192.168.2.36",
                "vhost": "/",
                "use_ssl": False,
                "port": 5672,
                "user": "guest",
                "pass": "guest",
            },
            "listen": "openbas_injector_openbas_mailer",
        }
        self.client = OpenBAS(
            url="http://localhost:3001/api",
            token="3207fa04-35d8-4baa-a735-17033abf101d",
        )
        self.helper = OpenBASInjectorHelper(self.client, config, injector_config)

    def _process_message(self, data: Dict) -> str:
        print(data)
        return "OK"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    openBASEmail = OpenBASEmail()
    openBASEmail.start()
