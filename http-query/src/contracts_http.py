from typing import List

from pyobas._contracts.contract_builder import ContractBuilder
from pyobas._contracts.contract_config import (
    Contract,
    ContractAttachment,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractText,
    ContractTextArea,
    ContractTuple,
    SupportedLanguage,
    prepare_contracts,
)

TYPE = "openbas_http"
HTTP_RAW_POST_CONTRACT = "5948c96c-4064-4c0d-b079-51ec33f31b91"
HTTP_RAW_PUT_CONTRACT = "bb503f7c-1f17-49e1-ac31-f4c2e99fd704"
HTTP_FORM_POST_CONTRACT = "a4794081-ccb5-41ef-9855-304ad5fdf4a9"
HTTP_FORM_PUT_CONTRACT = "d11d7694-29d1-4c1a-b1d7-9fc4251f0466"
HTTP_GET_CONTRACT = "611f223d-0e95-4f5b-ad89-a09ec2be50ae"


class HttpContracts:

    @staticmethod
    def build_contract():
        # Config
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "HTTP Request",
                SupportedLanguage.fr: "Requête HTTP",
            },
            color_dark="#00bcd4",
            color_light="#00bcd4",
            icon="/img/http.png",
            expose=True,
        )
        basic_auth_field = ContractCheckbox(
            key="basicAuth",
            label="Use basic authentication",
            defaultValue=False,
            mandatory=False,
        )
        username_field = ContractText(
            key="basicUser",
            label="Username",
            defaultValue="",
            mandatory=False,
            linkedFields=[basic_auth_field],
        )
        basic_password = ContractText(
            key="basicPassword",
            label="Password",
            defaultValue="",
            mandatory=False,
            linkedFields=[basic_auth_field],
        )
        auth_fields = [basic_auth_field, username_field, basic_password]
        # Post contract raw
        raw_post_instance: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="URL"))
            .add_fields(auth_fields)
            .optional(ContractTuple(key="headers", label="Headers"))
            .mandatory(ContractTextArea(key="body", label="Raw request data"))
            .build()
        )
        raw_post_contract = Contract(
            contract_id=HTTP_RAW_POST_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - POST (raw body)",
                SupportedLanguage.fr: "Requête HTTP - POST (body brut)",
            },
            fields=raw_post_instance,
            manual=False,
        )
        raw_put_contract = Contract(
            contract_id=HTTP_RAW_PUT_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - PUT (raw body)",
                SupportedLanguage.fr: "Requête HTTP - PUT (body brut)",
            },
            fields=raw_post_instance,
            manual=False,
        )
        # Post contract form
        attachment_field = ContractAttachment(
            key="attachments",
            label="Attachments",
            cardinality=ContractCardinality.Multiple,
        )
        form_post_instance: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="URL"))
            .add_fields(auth_fields)
            .optional(ContractTuple(key="headers", label="Headers"))
            .optional(
                ContractTuple(
                    key="parts",
                    label="Form request data",
                    attachmentKey=attachment_field.key,
                )
            )
            .optional(attachment_field)
            .build()
        )
        form_post_contract = Contract(
            contract_id=HTTP_FORM_POST_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - POST (key/value)",
                SupportedLanguage.fr: "Requête HTTP - POST (clé/valeur)",
            },
            fields=form_post_instance,
            manual=False,
        )
        form_put_contract = Contract(
            contract_id=HTTP_FORM_PUT_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - PUT (key/value)",
                SupportedLanguage.fr: "Requête HTTP - PUT (clé/valeur)",
            },
            fields=form_post_instance,
            manual=False,
        )
        # Get contract
        get_instance: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="URL"))
            .add_fields(auth_fields)
            .optional(ContractTuple(key="headers", label="Headers"))
            .build()
        )
        get_contract = Contract(
            contract_id=HTTP_GET_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - GET",
                SupportedLanguage.fr: "Requête HTTP - GET",
            },
            fields=get_instance,
            manual=False,
        )
        return prepare_contracts(
            [
                raw_post_contract,
                form_post_contract,
                raw_put_contract,
                form_put_contract,
                get_contract,
            ]
        )
