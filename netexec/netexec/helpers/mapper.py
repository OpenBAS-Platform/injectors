from typing import Dict


class Mapper:

    @staticmethod
    def get_inject_id(data: Dict):
        return data["injection"]["inject_id"]

    @staticmethod
    def get_contract_id(data: Dict):
        return data["injection"]["inject_injector_contract"]["convertedContent"]["contract_id"]

    @staticmethod
    def get_content(data: Dict):
        return data["injection"]["inject_content"]
