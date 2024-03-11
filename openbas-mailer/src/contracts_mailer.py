from typing import List

from pybas._contracts.contract_builder import ContractBuilder
from pybas._contracts.contract_config import (
    ContractAttachment,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractTeam,
    ContractText,
    ContractTextArea,
    SupportedLanguage,
    Contract,
)
from pybas._contracts.contract_utils import ContractVariable, VariableType


TYPE = "openbas_mailer"
EMAIL_DEFAULT = "138ad8f8-32f8-4a22-8114-aaa12322bd11"
EMAIL_GLOBAL = "2790bd39-37d4-4e39-be7e-53f3ca783f11"


class EmailContracts:

    @staticmethod
    def build_contract():
        # Variables
        document_uri_variable = ContractVariable(
            key="document_uri",
            label="Http user link to upload the document (only for document expectation)",
            type=VariableType.String,
            cardinality=ContractCardinality.One,
        )
        # Config
        contract_config = ContractConfig(
            type=TYPE,
            label={SupportedLanguage.en: "Email", SupportedLanguage.fr: "Email"},
            color_dark="#cddc39",
            color_light="#cddc39",
            icon="/img/email.png",
            expose=True,
        )
        expectation_field = ContractExpectations(
            key="expectations", label="Expectations"
        )
        team_field = ContractTeam(
            key="teams", label="Teams", cardinality=ContractCardinality.Multiple
        )
        encrypted_field = ContractCheckbox(
            key="encrypted", label="Encrypted", defaultValue=False
        )
        attachment_field = ContractAttachment(
            key="attachments",
            label="Attachments",
            cardinality=ContractCardinality.Multiple,
        )
        subject_field = ContractText(key="subject", label="Subject")
        body_field = ContractTextArea(key="body", label="Body")
        # standard_email
        standard_email_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(team_field)
            .mandatory(subject_field)
            .mandatory(body_field)
            .optional(encrypted_field)
            .optional(attachment_field)
            .optional(expectation_field)
            .build()
        )
        standard_email = Contract(
            contract_id=EMAIL_DEFAULT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Send individual mails (mailer)",
                SupportedLanguage.fr: "Envoyer des mails individuels (mailer)",
            },
            fields=standard_email_fields,
            manual=False,
        )
        standard_email.add_variable(document_uri_variable)
        # global_email
        global_email_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(team_field)
            .mandatory(subject_field)
            .mandatory(body_field)
            .optional(attachment_field)
            .optional(expectation_field)
            .build()
        )
        global_email = Contract(
            contract_id=EMAIL_GLOBAL,
            config=contract_config,
            label={
                SupportedLanguage.en: "Send multi-recipients mail (mailer)",
                SupportedLanguage.fr: "Envoyer un mail multi-destinataires (mailer)",
            },
            fields=global_email_fields,
            manual=False,
        )
        global_email.add_variable(document_uri_variable)
        return [standard_email, global_email]
