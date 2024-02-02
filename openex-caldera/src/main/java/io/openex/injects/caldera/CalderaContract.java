package io.openex.injects.caldera;

import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.ContractDef;
import io.openex.contract.Contractor;
import io.openex.contract.fields.ContractAsset;
import io.openex.contract.fields.ContractAssetGroup;
import io.openex.contract.fields.ContractExpectations;
import io.openex.contract.fields.ContractSelect;
import io.openex.helper.SupportedLanguage;
import io.openex.injects.caldera.client.model.Ability;
import io.openex.injects.caldera.config.InjectorCalderaConfig;
import io.openex.injects.caldera.model.Obfuscator;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.model.inject.form.Expectation;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractCardinality.Multiple;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractAsset.assetField;
import static io.openex.contract.fields.ContractAssetGroup.assetGroupField;
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
