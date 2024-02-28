package io.openbas.injects.lade;

import io.openbas.contract.Contract;
import io.openbas.contract.ContractConfig;
import io.openbas.contract.Contractor;
import io.openbas.injects.lade.config.LadeConfig;
import io.openbas.injects.lade.service.LadeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.openbas.helper.SupportedLanguage.en;

@Component
public class LadeContract extends Contractor {

    public static final String TYPE = "openbas_lade";
    private LadeConfig config;
    private LadeService ladeService;

    @Autowired
    public void setLadeService(LadeService ladeService) {
        this.ladeService = ladeService;
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
        return new ContractConfig(TYPE, Map.of(en, "Airbus LADE"), "#673AB7", "#673AB7", "/img/airbus.png", isExpose());
    }

    @Autowired
    public void setConfig(LadeConfig config) {
        this.config = config;
    }

    @Override
    public List<Contract> contracts() throws Exception {
        if (Optional.ofNullable(config.getEnable()).orElse(false)) {
            ContractConfig contractConfig = getConfig();
            return ladeService.buildContracts(contractConfig);
        }
        return List.of();
    }
}
