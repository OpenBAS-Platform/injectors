package io.openex.injects.lade;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.Contractor;
import io.openex.injects.lade.config.LadeConfig;
import io.openex.injects.lade.service.LadeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static io.openex.helper.SupportedLanguage.en;

@Component
public class LadeContract extends Contractor {

    public static final String TYPE = "openex_lade";
    private LadeConfig config;
    private LadeService ladeService;

    @Autowired
    public void setLadeService(LadeService ladeService) {
        this.ladeService = ladeService;
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
        return new ContractConfig(TYPE, Map.of(en, "Airbus LADE"), "#673AB7", "/img/airbus.png", isExpose());
    }

    @Autowired
    public void setConfig(LadeConfig config) {
        this.config = config;
    }

    @Override
    public List<Contract> contracts() throws Exception {
        ContractConfig contractConfig = getConfig();
        return ladeService.buildContracts(contractConfig);
    }
}
