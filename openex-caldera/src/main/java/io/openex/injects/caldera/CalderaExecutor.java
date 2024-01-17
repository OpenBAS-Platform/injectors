package io.openex.injects.caldera;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.openex.contract.Contract;
import io.openex.database.model.Asset;
import io.openex.database.model.Execution;
import io.openex.database.model.Inject;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.model.Expectation;
import io.openex.service.AssetGroupService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceInfo;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.injects.caldera.CalderaContract.CALDERA_SOURCE;
import static org.springframework.util.StringUtils.hasText;

@Component(CalderaContract.TYPE)
@RequiredArgsConstructor
public class CalderaExecutor extends Injector {

  private final InjectorCalderaService calderaService;
  private final AssetGroupService assetGroupService;

  @Override
  public List<Expectation> process(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection,
      @NotNull final Contract contract) {
    Inject inject = injection.getInject();
    ObjectNode content = inject.getContent();
    String obfuscator = content.get("obfuscator").asText();
    List<String> endpoints = new java.util.ArrayList<>();

    if (content.get("endpoint") != null && hasText(content.get("endpoint").asText())) {
      endpoints.add(content.get("endpoint").asText());
    }

    if (content.get("assetgroup") != null && hasText(content.get("assetgroup").asText())) {
      String assetGroupId = content.get("assetgroup").asText();
      List<Asset> assets = this.assetGroupService.assetsFromAssetGroup(assetGroupId);
      // Filter on Caldera source
      endpoints.addAll(
          assets.stream()
              .filter((a) -> a.getSources().get(CALDERA_SOURCE) != null)
              .map((a) -> a.getSources().get(CALDERA_SOURCE))
              .toList()
      );
    }

    List<String> asyncIds = new ArrayList<>();
    for (String endpoint : endpoints) {
      try {
        this.calderaService.exploit(obfuscator, endpoint, contract.getId());
        String linkId = this.calderaService.linkId(endpoint, contract.getId());
        asyncIds.add(linkId);
        String message = "Caldera execute ability " + contract.getLabel().get(en) + " on endpoint " + endpoint;
        execution.addTrace(traceInfo("caldera", message));
      } catch (Exception e) {
        execution.addTrace(traceError("caldera", e.getMessage(), e));
      }
      execution.setAsyncIds(asyncIds.toArray(new String[0]));
    }
    return List.of();
  }

}
