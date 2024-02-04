package io.openex.injects.ovh_sms;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractElement;
import io.openex.contract.fields.ContractExpectations;
import io.openex.injects.ovh_sms.config.OvhSmsConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractCardinality.Multiple;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractTeam.teamField;
import static io.openex.contract.fields.ContractExpectations.expectationsField;
import static io.openex.contract.fields.ContractTextArea.textareaField;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.helper.SupportedLanguage.fr;

@Component
public class OvhSmsContract extends Contractor {

    public static final String TYPE = "openex_ovh_sms";

    public static final String OVH_DEFAULT = "e9e902bc-b03d-4223-89e1-fca093ac79dd";

    private OvhSmsConfig config;

    @Autowired
    public void setConfig(OvhSmsConfig config) {
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
        return new ContractConfig(TYPE, Map.of(en, "SMS (OVH)"), "#9c27b0", "#9c27b0", "/img/sms.png", isExpose());
    }

    @Override
    public List<Contract> contracts() {
        ContractConfig contractConfig = getConfig();
        ContractExpectations expectationsField = expectationsField(
                "expectations", "Expectations"
        );
        List<ContractElement> instance = contractBuilder()
                .mandatory(teamField("teams", "Teams", Multiple))
                .mandatory(textareaField("message", "Message"))
                .optional(expectationsField)
                .build();
        return List.of(executableContract(contractConfig, OVH_DEFAULT,
                Map.of(en, "Send a SMS", fr, "Envoyer un SMS"), instance));
    }
}