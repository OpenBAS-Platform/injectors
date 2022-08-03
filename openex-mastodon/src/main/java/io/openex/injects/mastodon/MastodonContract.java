package io.openex.injects.mastodon;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractElement;
import io.openex.contract.fields.ContractNumber;
import io.openex.contract.fields.ContractSelect;
import io.openex.injects.mastodon.config.MastodonConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractCardinality.Multiple;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractAttachment.attachmentField;
import static io.openex.contract.fields.ContractText.textField;
import static io.openex.contract.fields.ContractNumber.numberField;
import static io.openex.contract.fields.ContractTextArea.textareaField;
import static io.openex.helper.SupportedLanguage.en;

@Component
public class MastodonContract extends Contractor {

    public static final String TYPE = "openex_mastodon";

    public static final String MASTODON_DEFAULT = "aeab9ed6-ae98-4b48-b8cc-2e91ac54f2f9";

    private MastodonConfig config;

    @Autowired
    public void setConfig(MastodonConfig config) {
        this.config = config;
    }

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
        return new ContractConfig(TYPE, Map.of(en, "Mastodon"), "#ad1457", "/img/mastodon.png", isExpose());
    }

    @Override
    public List<Contract> contracts() {
        ContractConfig contractConfig = getConfig();
        HashMap<String, String> choices = new HashMap<>();
        choices.put("none", "-");
        choices.put("manual", "The animation team can validate the audience reaction");
        // choices.put("document", "Each audience should upload a document");
        // choices.put("text", "Each audience should submit a text response");
        ContractSelect expectationSelect = ContractSelect
                .selectFieldWithDefault("expectationType", "Expectation", choices, "none");
        expectationSelect.setExpectation(true);
        ContractNumber expectationScore = numberField("expectationScore", "Expectation score", "0", List.of(expectationSelect), List.of("document", "text", "manual"));
        expectationScore.setExpectation(true);
        List<ContractElement> instance = contractBuilder()
                .mandatory(textField("token", "Token"))
                .mandatory(textareaField("status", "Status"))
                .optional(attachmentField("attachments", "Attachments", Multiple))
                .mandatory(expectationSelect)
                .optional(expectationScore)
                .build();
        return List.of(executableContract(contractConfig, MASTODON_DEFAULT, Map.of(en, "Mastodon"), instance));
    }
}
