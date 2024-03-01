package io.openbas.injects.mastodon;

import io.openbas.contract.Contract;
import io.openbas.contract.ContractConfig;
import io.openbas.contract.Contractor;
import io.openbas.contract.fields.ContractElement;
import io.openbas.injects.mastodon.config.MastodonConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.openbas.contract.Contract.executableContract;
import static io.openbas.contract.ContractCardinality.Multiple;
import static io.openbas.contract.ContractDef.contractBuilder;
import static io.openbas.contract.fields.ContractAttachment.attachmentField;
import static io.openbas.contract.fields.ContractText.textField;
import static io.openbas.contract.fields.ContractTextArea.textareaField;
import static io.openbas.helper.SupportedLanguage.en;

@Component
public class MastodonContract extends Contractor {

    public static final String TYPE = "openbas_mastodon";

    public static final String MASTODON_DEFAULT = "aeab9ed6-ae98-4b48-b8cc-2e91ac54f2f9";

    private MastodonConfig config;

    @Autowired
    public void setConfig(MastodonConfig config) {
        this.config = config;
    }

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
        return new ContractConfig(TYPE, Map.of(en, "Mastodon"), "#ad1457", "#ad1457", "/img/mastodon.png", isExpose());
    }

    @Override
    public List<Contract> contracts() {
        ContractConfig contractConfig = getConfig();
        List<ContractElement> instance = contractBuilder()
                .mandatory(textField("token", "Token"))
                .mandatory(textareaField("status", "Status"))
                .optional(attachmentField("attachments", "Attachments", Multiple)).build();
        return List.of(executableContract(contractConfig, MASTODON_DEFAULT, Map.of(en, "Mastodon"), instance));
    }
}
