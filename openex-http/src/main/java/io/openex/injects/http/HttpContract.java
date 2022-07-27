package io.openex.injects.http;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractElement;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.http.config.HttpConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractCardinality.Multiple;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractAttachment.attachmentField;
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
        return config.getEnable();
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public ContractConfig getConfig() {
        Map<SupportedLanguage, String> labels = Map.of(en, "HTTP Request", fr, "Requête HTTP");
        return new ContractConfig(TYPE, labels, "#00bcd4", "/img/http.png", isExpose());
    }

    @Autowired
    public void setConfig(HttpConfig config) {
        this.config = config;
    }

    @Override
    public List<Contract> contracts() {
        ContractConfig contractConfig = getConfig();
        // Post contract raw
        List<ContractElement> rawPostInstance = contractBuilder()
                .mandatory(textField("uri", "URL"))
                .optional(tupleField("headers", "Headers"))
                .mandatory(textareaField("body", "Raw request data"))
                .build();
        Contract rawPostContract = executableContract(contractConfig, HTTP_RAW_POST_CONTRACT,
                Map.of(en, "HTTP Request - POST RAW", fr, "Requête HTTP - POST RAW"), rawPostInstance);
        Contract rawPutContract = executableContract(contractConfig, HTTP_RAW_PUT_CONTRACT,
                Map.of(en, "HTTP Request - PUT RAW", fr, "Requête HTTP - PUT RAW"), rawPostInstance);
        // Post contract form
        List<ContractElement> formPostInstance = contractBuilder()
                .mandatory(textField("uri", "URL"))
                .optional(tupleField("headers", "Headers"))
                .mandatory(tupleField("parts", "Form request data"))
                .optional(attachmentField("attachments", "Attachments", Multiple))
                .build();
        Contract formPostContract = executableContract(contractConfig, HTTP_FORM_POST_CONTRACT,
                Map.of(en, "HTTP Request - POST FORM", fr, "Requête HTTP - POST FORM"), formPostInstance);
        Contract formPutContract = executableContract(contractConfig, HTTP_FORM_PUT_CONTRACT,
                Map.of(en, "HTTP Request - PUT FORM", fr, "Requête HTTP - PUT FORM"), formPostInstance);
        // Get contract
        List<ContractElement> getInstance = contractBuilder()
                .mandatory(textField("uri", "URL"))
                .optional(tupleField("headers", "Headers")).build();
        Contract getContract = executableContract(contractConfig, HTTP_GET_CONTRACT,
                Map.of(en, "HTTP Request - GET", fr, "Requête HTTP - GET"), getInstance);
        return List.of(rawPostContract, formPostContract, rawPutContract, formPutContract, getContract);
    }
}
