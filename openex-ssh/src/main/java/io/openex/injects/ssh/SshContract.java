package io.openex.injects.ssh;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractElement;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.ssh.config.SshConfig;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractNumber.numberField;
import static io.openex.contract.fields.ContractText.textField;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.helper.SupportedLanguage.fr;

@Getter
@Setter
@Component
public class SshContract extends Contractor {
    public static final String TYPE = "openex_ssh";
    public static final String SSH_CONTRACT = "27d3a40f-8868-47a4-a4b4-d7b98b0c790a";

    private SshConfig config;

    @Override
    public boolean isExpose() {
        return this.config.getEnable();
    }

    @Override
    public String getType() {
        return TYPE;
    }

    // Used for the list
    @Override
    public ContractConfig getConfig() {
        Map<SupportedLanguage, String> labels = Map.of(en, "SSH", fr, "SSH");
        return new ContractConfig(TYPE, labels, "#6300d4", null, isExpose());
    }

    @Autowired
    public void setConfig(@NotNull final SshConfig config) {
        this.config = config;
    }

    @Override
    public List<Contract> contracts() {
        ContractConfig contractConfig = this.getConfig();
        List<ContractElement> getInstance = contractBuilder()
                .mandatory(textField("username", "Username"))
                .mandatory(textField("password", "Password"))
                .mandatory(textField("host", "Host"))
                .mandatory(numberField("port", "Port", "22"))
                .mandatory(textField("command", "Command"))
                .build();
        Contract contract = executableContract(contractConfig, SSH_CONTRACT, Map.of(en, "SSH or Powershell remoting", fr, "Accès à distance SSH ou Powershell"), getInstance);
        return List.of(contract);
    }
}
