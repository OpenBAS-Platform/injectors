package io.openex.injects.http;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractAttachment;
import io.openex.contract.fields.ContractCheckbox;
import io.openex.contract.fields.ContractElement;
import io.openex.contract.fields.ContractText;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.http.config.HttpConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractCardinality.Multiple;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractAttachment.attachmentField;
import static io.openex.contract.fields.ContractCheckbox.checkboxField;
import static io.openex.contract.fields.ContractText.textField;
import static io.openex.contract.fields.ContractTextArea.textareaField;
import static io.openex.contract.fields.ContractTuple.tupleField;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.helper.SupportedLanguage.fr;

@Component
public class HttpContract extends Contractor {

  public static final String TYPE = "openex_http";
  public static final String HTTP_RAW_POST_CONTRACT = "5948c96c-4064-4c0d-b079-51ec33f31b91";
  public static final String HTTP_RAW_PUT_CONTRACT = "bb503f7c-1f17-49e1-ac31-f4c2e99fd704";
  public static final String HTTP_FORM_POST_CONTRACT = "a4794081-ccb5-41ef-9855-304ad5fdf4a9";
  public static final String HTTP_FORM_PUT_CONTRACT = "d11d7694-29d1-4c1a-b1d7-9fc4251f0466";
  public static final String HTTP_GET_CONTRACT = "611f223d-0e95-4f5b-ad89-a09ec2be50ae";

  private HttpConfig config;

  @Override
  public boolean isExpose() {
        return Optional.ofNullable(config.getEnable()).orElse(false);
  }

  @Override
  public String getType() {
    return TYPE;
  }

  @Override
  public ContractConfig getConfig() {
    Map<SupportedLanguage, String> labels = Map.of(en, "HTTP Request", fr, "Requête HTTP");
    return new ContractConfig(TYPE, labels, "#00bcd4", "#00bcd4", "/img/http.png", isExpose());
  }

  @Autowired
  public void setConfig(HttpConfig config) {
    this.config = config;
  }

  @Override
  public List<Contract> contracts() {
    ContractConfig contractConfig = getConfig();
    // Basic auth contract
    ContractCheckbox basicAuthField = checkboxField("basicAuth", "Use basic authentication", false);
    basicAuthField.setMandatory(false);
    ContractText usernameField = textField("basicUser", "Username", "", List.of(basicAuthField));
    usernameField.setMandatory(false);
    ContractText passwordField = textField("basicPassword", "Password", "", List.of(basicAuthField));
    passwordField.setMandatory(false);
    List<ContractElement> authFields = List.of(basicAuthField, usernameField, passwordField);
    // Post contract raw
    List<ContractElement> rawPostInstance = contractBuilder()
        .mandatory(textField("uri", "URL"))
        .addFields(authFields)
        .optional(tupleField("headers", "Headers"))
        .mandatory(textareaField("body", "Raw request data"))
        .build();
    Contract rawPostContract = executableContract(contractConfig, HTTP_RAW_POST_CONTRACT,
        Map.of(en, "HTTP Request - POST (raw body)", fr, "Requête HTTP - POST (body brut)"), rawPostInstance);
    Contract rawPutContract = executableContract(contractConfig, HTTP_RAW_PUT_CONTRACT,
        Map.of(en, "HTTP Request - PUT (raw body)", fr, "Requête HTTP - PUT (body brut)"), rawPostInstance);
    // Post contract form
    ContractAttachment attachmentContract = attachmentField("attachments", "Attachments", Multiple);
    List<ContractElement> formPostInstance = contractBuilder()
        .mandatory(textField("uri", "URL"))
        .addFields(authFields)
        .optional(tupleField("headers", "Headers"))
        .mandatory(tupleField("parts", "Form request data", attachmentContract))
        .optional(attachmentContract)
        .build();
    Contract formPostContract = executableContract(contractConfig, HTTP_FORM_POST_CONTRACT,
        Map.of(en, "HTTP Request - POST (key/value)", fr, "Requête HTTP - POST (clé/valeur)"), formPostInstance);
    Contract formPutContract = executableContract(contractConfig, HTTP_FORM_PUT_CONTRACT,
        Map.of(en, "HTTP Request - PUT (key/value)", fr, "Requête HTTP - PUT (clé/valeur)"), formPostInstance);
    // Get contract
    List<ContractElement> getInstance = contractBuilder()
        .mandatory(textField("uri", "URL"))
        .addFields(authFields)
        .optional(tupleField("headers", "Headers"))
        .build();
    Contract getContract = executableContract(contractConfig, HTTP_GET_CONTRACT,
        Map.of(en, "HTTP Request - GET", fr, "Requête HTTP - GET"), getInstance);
    return List.of(rawPostContract, formPostContract, rawPutContract, formPutContract, getContract);
  }
}
