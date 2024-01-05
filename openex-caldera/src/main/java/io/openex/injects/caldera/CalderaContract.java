package io.openex.injects.caldera;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.ContractDef;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractSelect;
import io.openex.database.model.Endpoint;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.caldera.client.model.Ability;
import io.openex.injects.caldera.config.InjectorCalderaConfig;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.service.AssetEndpointService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractSelect.selectFieldWithDefault;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.helper.SupportedLanguage.fr;

@Component
@RequiredArgsConstructor
public class CalderaContract extends Contractor {

  public static final String TYPE = "openex_caldera";

  private final InjectorCalderaConfig config;
  private final InjectorCalderaService injectorCalderaService;
  private final AssetEndpointService assetEndpointService;

  @Override
  protected boolean isExpose() {
    return this.config.isEnable();
  }

  @Override
  protected String getType() {
    return TYPE;
  }

  @Override
  public ContractConfig getConfig() {
    Map<SupportedLanguage, String> labels = Map.of(en, "Caldera", fr, "Caldera");
    return new ContractConfig(TYPE, labels, "#8b0000", "/img/caldera.png", isExpose());
  }

  @Override
  public List<Contract> contracts() {
    if (this.config.isEnable()) {
      ContractConfig contractConfig = getConfig();
      // Add contract bases on abilities
      return new ArrayList<>(abilityContracts(contractConfig));
    }
    return List.of();
  }

  // -- PRIVATE --

  private Map<String, String> endpointChoices() {
    List<Endpoint> endpoints = this.assetEndpointService.endpoints();
    return endpoints.stream()
        .collect(Collectors.toMap(Endpoint::getName, e -> e.getName() + "-" + e.getHostname()));
  }

  private List<Contract> abilityContracts(@NotNull final ContractConfig contractConfig) {
    Map<String, String> endpointChoices = endpointChoices();
    ContractSelect endpointField = selectFieldWithDefault(
        "endpoint",
        "Endpoints",
        endpointChoices,
        endpointChoices.keySet().stream().findFirst().orElseThrow()
    );
    List<Ability> abilities = this.injectorCalderaService.abilities();
    // Build contracts
    return abilities.stream().map((ability -> {
      ContractDef builder = contractBuilder();
      builder.mandatory(endpointField);
      return executableContract(
          contractConfig,
          ability.getAbility_id(),
          Map.of(en, ability.getName()),
          builder.build()
      );
    })).collect(Collectors.toList());
  }
}
