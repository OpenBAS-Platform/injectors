package io.openbas.injects.caldera.service;

import io.openbas.asset.AssetGroupService;
import io.openbas.database.model.*;
import io.openbas.database.repository.InjectRepository;
import io.openbas.database.repository.InjectStatusRepository;
import io.openbas.injectExpectation.InjectExpectationService;
import io.openbas.injects.caldera.CalderaContract;
import io.openbas.injects.caldera.config.InjectorCalderaConfig;
import io.openbas.injects.caldera.model.ResultStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static io.openbas.database.model.InjectStatusExecution.traceInfo;
import static io.openbas.injectExpectation.InjectExpectationUtils.resultsBySourceId;
import static io.openbas.injects.caldera.config.InjectorCalderaConfig.PRODUCT_NAME;

@Service
@RequiredArgsConstructor
public class InjectorCalderaListener {

  private final InjectRepository injectRepository;
  private final InjectStatusRepository injectStatusRepository;
  private final InjectExpectationService injectExpectationService;
  private final InjectorCalderaService calderaService;
  private final InjectorCalderaConfig injectorCalderaConfig;
  private final AssetGroupService assetGroupService;

  @Scheduled(fixedDelay = 60000, initialDelay = 0)
  @Transactional
  public void listenAbilities() {
    // Retrieve Caldera inject not done
    List<InjectStatus> injectStatuses = this.injectStatusRepository.pendingForInjectType(CalderaContract.TYPE);
    // For each one ask for traces and status
    injectStatuses.forEach((injectStatus -> {
      Inject inject = injectStatus.getInject();
      // Add traces and close inject if needed.
      Instant finalExecutionTime = injectStatus.getTrackingSentDate();

      List<Asset> assets = injectStatus.getInject().getAssets();
      List<AssetGroup> assetGroups = injectStatus.getInject().getAssetGroups();
      List<Asset> totalAssets = new ArrayList<>(assetGroups.stream()
          .flatMap((assetGroup -> this.assetGroupService.assetsFromAssetGroup(assetGroup.getId()).stream()))
          .distinct()
          .toList());
      totalAssets.addAll(assets);

      List<String> linkIds = injectStatus.statusIdentifiers();
      List<ResultStatus> completedActions = new ArrayList<>();
      for (String linkId : linkIds) {
        try {
          ResultStatus resultStatus = this.calderaService.results(linkId);

          String currentAssetId = totalAssets.stream()
              .filter((a) -> a.getSources().containsValue(resultStatus.getPaw()))
              .findFirst()
              .map(Asset::getId)
              .orElseThrow();

          if (resultStatus.isComplete()) {
            completedActions.add(resultStatus);

            computeExpectationForAsset(inject, currentAssetId, resultStatus.isFail(), resultStatus.getContent());

            // Compute biggest execution time
            if (resultStatus.getFinish().isAfter(finalExecutionTime)) {
              finalExecutionTime = resultStatus.getFinish();
            }
          // TimeOut
          } else if (injectStatus.getDate().isBefore(Instant.now().minus(5L, ChronoUnit.MINUTES))) {
            resultStatus.setFail(true);
            completedActions.add(resultStatus);

            computeExpectationForAsset(inject, currentAssetId, resultStatus.isFail(), "Time out");
          }
        } catch (Exception e) {
          // injectStatus.getReporting().addTrace(
          //     traceError("caldera", "Caldera error to execute ability", e)
          // );
        }
      }

      // Compute status only if all actions are completed
      if (completedActions.size() == linkIds.size()) {
        assetGroups.forEach((assetGroup -> computeExpectationForAssetGroup(inject, assetGroup)));
        int failedActions = (int) completedActions.stream().filter(ResultStatus::isFail).count();
        computeInjectStatus(injectStatus, finalExecutionTime, completedActions.size(), failedActions);
        // Update related inject
        computeInject(injectStatus);
      }
    }));
  }

  // -- EXPECTATION --

  private void computeExpectationForAsset(
      @NotNull final Inject inject,
      @NotBlank final String assetId,
      @NotNull final boolean fail, // Is action failed, success for expectation
      @NotBlank final String result) {
    InjectExpectation expectation = this.injectExpectationService
        .preventionExpectationForAsset(inject, assetId);
    if (expectation != null) {
      // Not already handle
      List<InjectExpectationResult> results = resultsBySourceId(expectation, this.injectorCalderaConfig.getId());
      if (results.isEmpty()) {
        this.injectExpectationService.computeExpectation(
            expectation,
            this.injectorCalderaConfig.getId(),
            PRODUCT_NAME,
            result,
            fail);
      }
    }
  }

  private void computeExpectationForAssetGroup(
      @NotNull final Inject inject,
      @NotBlank final AssetGroup assetGroup) {
    InjectExpectation expectationAssetGroup = this.injectExpectationService
        .preventionExpectationForAssetGroup(inject, assetGroup);
    if (expectationAssetGroup != null) {
      List<InjectExpectation> expectationAssets = this.injectExpectationService
          .preventionExpectationForAssets(inject, assetGroup);
      // Not already handle
      List<InjectExpectationResult> results = resultsBySourceId(
          expectationAssetGroup,
          this.injectorCalderaConfig.getId()
      );
      if (results.isEmpty()) {
        this.injectExpectationService.computeExpectationGroup(
            expectationAssetGroup,
            expectationAssets,
            this.injectorCalderaConfig.getId(),
            PRODUCT_NAME
        );
      }
    }
  }

  // -- INJECT STATUS --

  private void computeInjectStatus(
      @NotNull final InjectStatus injectStatus,
      @NotNull final Instant finalExecutionTime,
      final int completedActions,
      final int failedActions) {
    // boolean hasError = injectStatus.getReporting().getTraces().stream()
    //     .anyMatch(trace -> trace.getStatus().equals(ExecutionStatus.ERROR));
    // injectStatus.setName(hasError ? ExecutionStatus.ERROR.name() : ExecutionStatus.SUCCESS.name());
    // injectStatus.getReporting().addTrace(
    //     traceInfo("caldera",
    //         "Caldera success to execute ability on " + (completedActions - failedActions)
    //             + "/" + completedActions + " asset(s)")
    // );
    long executionTime = (finalExecutionTime.toEpochMilli() - injectStatus.getTrackingSentDate().toEpochMilli());
    injectStatus.setTrackingTotalExecutionTime(executionTime);
    this.injectStatusRepository.save(injectStatus);
  }

  // -- INJECT --

  private void computeInject(@NotNull final InjectStatus injectStatus) {
    Inject relatedInject = injectStatus.getInject();
    relatedInject.setUpdatedAt(Instant.now());
    this.injectRepository.save(relatedInject);
  }

}
