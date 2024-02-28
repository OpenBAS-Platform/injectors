package io.openbas.injects.caldera;

import io.openbas.contract.Contract;
import io.openbas.contract.ContractConfig;
import io.openbas.contract.ContractDef;
import io.openbas.contract.Contractor;
import io.openbas.contract.fields.ContractAsset;
import io.openbas.contract.fields.ContractAssetGroup;
import io.openbas.contract.fields.ContractExpectations;
import io.openbas.contract.fields.ContractSelect;
import io.openbas.helper.SupportedLanguage;
import io.openbas.injects.caldera.client.model.Ability;
import io.openbas.injects.caldera.config.InjectorCalderaConfig;
import io.openbas.injects.caldera.model.Obfuscator;
import io.openbas.injects.caldera.service.InjectorCalderaService;
import io.openbas.model.inject.form.Expectation;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.openbas.contract.Contract.executableContract;
import static io.openbas.contract.ContractCardinality.Multiple;
import static io.openbas.contract.ContractDef.contractBuilder;
import static io.openbas.contract.fields.ContractAsset.assetField;
import static io.openbas.contract.fields.ContractAssetGroup.assetGroupField;
import static io.openbas.contract.fields.ContractExpectations.expectationsField;
import static io.openbas.contract.fields.ContractSelect.selectFieldWithDefault;
import static io.openex.database.model.InjectExpectation.EXPECTATION_TYPE.DETECTION;
import static io.openbas.database.model.InjectExpectation.EXPECTATION_TYPE.TECHNICAL;
import static io.openbas.helper.SupportedLanguage.en;
import static io.openbas.helper.SupportedLanguage.fr;

@Component
@RequiredArgsConstructor
public class CalderaContract extends Contractor {

  public static final String TYPE = "openbas_caldera";

  private final InjectorCalderaConfig config;
  private final InjectorCalderaService injectorCalderaService;

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
    return new ContractConfig(TYPE, labels, "#8b0000", "#8b0000", "/img/caldera.png", isExpose());
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

  private ContractExpectations expectations() {
    // Technical
    Expectation technicalExpectation = new Expectation();
    technicalExpectation.setType(TECHNICAL);
    technicalExpectation.setName("Expect technical inject to failed");
    technicalExpectation.setScore(0);
    // Detection
    Expectation detectionExpectation = new Expectation();
    detectionExpectation.setType(DETECTION);
    detectionExpectation.setName("Expect inject to be detected");
    detectionExpectation.setScore(0);

    return expectationsField(
        "expectations", "Expectations", List.of(technicalExpectation, detectionExpectation)
    );
  }

  private List<Contract> abilityContracts(@NotNull final ContractConfig contractConfig) {
    // Fields
    ContractSelect obfuscatorField = obfuscatorField();
    ContractAsset assetField = assetField("assets", "Assets", Multiple);
    ContractAssetGroup assetGroupField = assetGroupField("assetgroups", "Asset groups",
        Multiple);
    // Expectations
    ContractExpectations expectationsField = expectations();

    List<Ability> abilities = this.injectorCalderaService.abilities();
    // Build contracts
    return abilities.stream().map((ability -> {
      ContractDef builder = contractBuilder();
      builder.mandatory(obfuscatorField);
      builder.mandatoryGroup(assetField, assetGroupField);
      builder.optional(expectationsField);
      Contract contract = executableContract(
          contractConfig,
          ability.getAbility_id(),
          Map.of(en, ability.getName(), fr, ability.getName()),
          builder.build()
      );
      contract.addContext("collector-ids", String.join(", ", this.config.getCollectorIds()));
      return contract;
    })).collect(Collectors.toList());
  }
}
