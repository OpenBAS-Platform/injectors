package io.openex.injects.caldera;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.ContractDef;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractSelect;
import io.openex.database.model.AssetGroup;
import io.openex.database.model.Endpoint;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.caldera.client.model.Ability;
import io.openex.injects.caldera.config.InjectorCalderaConfig;
import io.openex.injects.caldera.model.Obfuscator;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.service.AssetEndpointService;
import io.openex.service.AssetGroupService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
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
  public static final String CALDERA_SOURCE = "Caldera";

  private final InjectorCalderaConfig config;
  private final InjectorCalderaService injectorCalderaService;
  private final AssetEndpointService assetEndpointService;
  private final AssetGroupService assetGroupService;

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

  private Map<String, String> obfuscatorChoices() {
    List<Obfuscator> obfuscators = this.injectorCalderaService.obfuscators();
    return obfuscators.stream().collect(Collectors.toMap(Obfuscator::getName, Obfuscator::getName));
  }

  private Map<String, String> endpointChoices() {
    List<Endpoint> endpoints = this.assetEndpointService.endpoints(); // TODO: limitation ?
    return endpoints.stream()
        .collect(Collectors.toMap(e -> e.getSources().get(CALDERA_SOURCE), e -> e.getName() + " - " + e.getHostname()));
  }

  private Map<String, String> assetGroupChoices() {
    List<AssetGroup> assetGroups = this.assetGroupService.assetGroups();
    return assetGroups.stream()
        .collect(Collectors.toMap(AssetGroup::getId, AssetGroup::getName)); // TODO: Display without checking source
  }

  private List<Contract> abilityContracts(@NotNull final ContractConfig contractConfig) {
    // Fields
    Map<String, String> obfuscatorChoices = obfuscatorChoices();
    ContractSelect obfuscatorField = selectFieldWithDefault(
        "obfuscator",
        "Obfuscators",
        obfuscatorChoices,
        obfuscatorChoices.keySet().stream().findFirst().orElseThrow()
    );
    Map<String, String> endpointChoices = endpointChoices();
    Map<String, String> endpointChoicesWithDefault = new HashMap<>() {{put("", "No value");}}; // First place
    endpointChoicesWithDefault.putAll(endpointChoices);
    ContractSelect endpointField = selectFieldWithDefault(
        "endpoint",
        "Endpoints",
        endpointChoicesWithDefault,
        ""
    );
    Map<String, String> assetGroupChoices = assetGroupChoices();
    Map<String, String> assetGroupChoicesWithDefault = new HashMap<>() {{put("", "No value");}}; // First place
    assetGroupChoicesWithDefault.putAll(assetGroupChoices);
    ContractSelect assetGroupField = selectFieldWithDefault(
        "assetgroup",
        "Asset groups",
        assetGroupChoicesWithDefault,
        ""
    );

    List<Ability> abilities = this.injectorCalderaService.abilities();
    // Build contracts
    return abilities.stream().map((ability -> {
      ContractDef builder = contractBuilder();
      builder.mandatory(obfuscatorField);
      builder.mandatoryGroup(endpointField, assetGroupField);
      return executableContract(
          contractConfig,
          ability.getAbility_id(),
          Map.of(en, ability.getName()),
          builder.build()
      );
    })).collect(Collectors.toList());
  }
}
