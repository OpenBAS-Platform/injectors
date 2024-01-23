package io.openex.injects.caldera;

import io.openex.contract.Contract;
import io.openex.database.model.Asset;
import io.openex.database.model.Endpoint;
import io.openex.database.model.Execution;
import io.openex.database.model.Inject;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.caldera.config.InjectorCalderaConfig;
import io.openex.injects.caldera.model.CalderaInjectContent;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.model.Expectation;
import io.openex.model.expectation.TechnicalExpectation;
import io.openex.service.AssetEndpointService;
import io.openex.service.AssetGroupService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.stream.Stream;

import static io.openex.database.model.ExecutionTrace.traceInfo;
import static io.openex.helper.SupportedLanguage.en;
import static org.springframework.util.StringUtils.hasText;

@Component(CalderaContract.TYPE)
@RequiredArgsConstructor
@Log
public class CalderaExecutor extends Injector {

  private final InjectorCalderaConfig config;
  private final InjectorCalderaService calderaService;
  private final AssetGroupService assetGroupService;
  private final AssetEndpointService assetEndpointService;

  @Override
  public List<Expectation> process(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection,
      @NotNull final Contract contract) throws Exception {
    CalderaInjectContent content = contentConvert(injection, CalderaInjectContent.class);
    String obfuscator = content.getObfuscator();

    List<Asset> assets = this.computeValidAsset(content);
    Map<String, Asset> paws = new HashMap<>();
    assets.forEach((a) -> {
      a.getSources().keySet().forEach((key) -> {
        if (this.config.getCollectorIds().contains(key)) {
          paws.put(a.getSources().get(key), a);
        }
      });
    });

    if (paws.isEmpty()) {
      throw new UnsupportedOperationException("Caldera inject needs at least one asset");
    }

    // Execute inject
    Map<String, Asset> executedAssetsMap = new HashMap<>();
    for (Map.Entry<String, Asset> entry : paws.entrySet()) {
      try {
        this.calderaService.exploit(obfuscator, entry.getKey(), contract.getId());
        String linkId = this.calderaService.linkId(entry.getKey(), contract.getId());
        executedAssetsMap.put(linkId, entry.getValue());
      } catch (Exception e) {
        log.log(Level.SEVERE, "Caldera failed to execute ability on asset " + entry.getValue().getId(), e.getMessage());
      }
    }
    String message = "Caldera execute ability " + contract.getLabel().get(en) + " on " + executedAssetsMap.size() + " asset(s)";
    execution.addTrace(traceInfo("caldera", message));
    execution.setAsyncIds(executedAssetsMap.keySet().toArray(new String[0]));

    // Compute expectations
    List<Asset> executedAssets = executedAssetsMap.values().stream().distinct().toList();
    List<Expectation> expectations = new ArrayList<>();
    if (!content.getExpectations().isEmpty()) {
      expectations.addAll(
          content.getExpectations()
              .stream()
              .flatMap((entry) -> switch (entry.getType()) {
                case TECHNICAL -> executedAssets.stream().map((asset) -> new TechnicalExpectation(entry.getScore(), asset, entry.isExpectationGroup()));
                default -> Stream.of();
              })
              .toList()
      );
    }
    return expectations;
  }

  // -- ASSET --

  @Override
  public List<Asset> assets(@NotNull final Inject inject) {
    try {
      CalderaInjectContent content = contentConvert(inject, CalderaInjectContent.class);
      return this.computeValidAsset(content);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private List<Asset> computeValidAsset(@NotNull final CalderaInjectContent content) {
    List<Asset> assets = new ArrayList<>();
    if (hasText(content.getEndpoint())) {
      String endpointId = content.getEndpoint();
      Endpoint endpoint = this.assetEndpointService.endpoint(endpointId);
      // Verify endpoint validity
      endpoint.getSources().keySet().forEach((key) -> {
        if (this.config.getCollectorIds().contains(key)) {
          assets.add(endpoint);
        }
      });
    }

    if (hasText(content.getAssetgroup())) {
      String assetGroupId = content.getAssetgroup();
      List<Asset> assetsFromGroup = this.assetGroupService.assetsFromAssetGroup(assetGroupId);
      // Verify endpoint validity
      assets.addAll(
          assetsFromGroup.stream()
              .flatMap((e) -> {
                List<Asset> selected = new ArrayList<>();
                e.getSources().keySet().forEach((key) -> {
                  if (this.config.getCollectorIds().contains(key)) {
                    selected.add(e);
                  }
                });
                return selected.stream();
              })
              .toList()
      );
    }
    return assets;
  }
}
