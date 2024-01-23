package io.openex.injects.caldera;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.ContractDef;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractExpectations;
import io.openex.contract.fields.ContractSelect;
import io.openex.database.model.AssetGroup;
import io.openex.database.model.Endpoint;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.caldera.client.model.Ability;
import io.openex.injects.caldera.config.InjectorCalderaConfig;
import io.openex.injects.caldera.model.Obfuscator;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.model.inject.form.Expectation;
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
import static io.openex.contract.fields.ContractExpectations.expectationsField;
import static io.openex.contract.fields.ContractSelect.selectFieldWithDefault;
import static io.openex.database.model.InjectExpectation.EXPECTATION_TYPE.TECHNICAL;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.helper.SupportedLanguage.fr;

@Component
@RequiredArgsConstructor
public class CalderaContract extends Contractor {

  public static final String TYPE = "openex_caldera";

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
      // Add contract based on abilities
      return new ArrayList<>(abilityContracts(contractConfig));
    }
    return List.of();
  }

  // -- PRIVATE --

  private ContractSelect obfuscatorField() {
    List<Obfuscator> obfuscators = this.injectorCalderaService.obfuscators();
    Map<String, String> obfuscatorChoices = obfuscators.stream()
        .collect(Collectors.toMap(Obfuscator::getName, Obfuscator::getName));
    return selectFieldWithDefault(
        "obfuscator",
        "Obfuscators",
        obfuscatorChoices,
        obfuscatorChoices.keySet().stream().findFirst().orElseThrow()
    );
  }

  private ContractSelect endpointField() {
    List<Endpoint> endpoints = this.assetEndpointService.endpoints();
    Map<String, String> endpointChoices = new HashMap<>();

    endpoints.forEach((e) -> e.getSources().keySet().forEach((key) -> {
      if (this.config.getCollectorIds().contains(key)) {
        endpointChoices.put(e.getId(), e.getName());
      }
    }));

    Map<String, String> endpointChoicesWithDefault = new HashMap<>() {{
      put("", "No value");
    }}; // First place
    endpointChoicesWithDefault.putAll(endpointChoices);
    return selectFieldWithDefault(
        "endpoint",
        "Endpoints",
        endpointChoicesWithDefault,
        ""
    );
  }

  private ContractSelect assetGroupField() {
    List<AssetGroup> assetGroups = this.assetGroupService.assetGroups();
    Map<String, String> assetGroupChoices = assetGroups.stream()
        .collect(Collectors.toMap(AssetGroup::getId, AssetGroup::getName));
    Map<String, String> assetGroupChoicesWithDefault = new HashMap<>() {{
      put("", "No value");
    }}; // First place
    assetGroupChoicesWithDefault.putAll(assetGroupChoices);
    return selectFieldWithDefault(
        "assetgroup",
        "Asset groups",
        assetGroupChoicesWithDefault,
        ""
    );
  }

  private ContractExpectations expectations() {
    Expectation expectation = new Expectation();
    expectation.setType(TECHNICAL);
    expectation.setName("Expect technical inject to failed");
    expectation.setScore(0);
    return expectationsField(
        "expectations", "Expectations", List.of(expectation)
    );
  }

  private List<Contract> abilityContracts(@NotNull final ContractConfig contractConfig) {
    // Fields
    ContractSelect obfuscatorField = obfuscatorField();
    ContractSelect endpointField = endpointField();
    ContractSelect assetGroupField = assetGroupField();
    // Expectations
    ContractExpectations expectationsField = expectations();

    List<Ability> abilities = this.injectorCalderaService.abilities();
    // Build contracts
    return abilities.stream().map((ability -> {
      ContractDef builder = contractBuilder();
      builder.mandatory(obfuscatorField);
      builder.mandatoryGroup(endpointField, assetGroupField);
      builder.optional(expectationsField);
      return executableContract(
          contractConfig,
          ability.getAbility_id(),
          Map.of(en, ability.getName(), fr, ability.getName()),
          builder.build()
      );
    })).collect(Collectors.toList());
  }
}
