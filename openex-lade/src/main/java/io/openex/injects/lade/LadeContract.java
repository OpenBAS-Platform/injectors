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
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.openex.helper.SupportedLanguage.en;

@Component
public class LadeContract extends Contractor {

    public static final String TYPE = "openex_lade";

    private static final Logger LOGGER = Logger.getLogger(LadeContract.class.getName());
    private LadeConfig config;
    private LadeService ladeService;

    @Autowired
    public void setLadeService(LadeService ladeService) {
        this.ladeService = ladeService;
    }

    @Autowired
    public void setConfig(LadeConfig config) {
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
        return new ContractConfig(TYPE, Map.of(en, "Airbus LADE"), "#673AB7", "/img/airbus.png", isExpose());
    }

    @Override
    public List<Contract> contracts() {
        ContractConfig contractConfig = getConfig();
        try {
            return ladeService.buildContracts(contractConfig);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "LADE failing generating the contracts", e);
            return List.of();
        }
    }
}
