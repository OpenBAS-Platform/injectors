package io.openbas.injects.caldera.service;

import io.openbas.database.model.*;
import io.openbas.database.repository.InjectExpectationRepository;
import io.openbas.database.repository.InjectRepository;
import io.openbas.database.repository.InjectStatusRepository;
import io.openbas.injects.caldera.CalderaContract;
import io.openbas.injects.caldera.model.ResultStatus;
import io.openbas.service.AssetGroupService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static io.openbas.database.model.ExecutionTrace.traceError;
import static io.openbas.database.model.ExecutionTrace.traceInfo;

@Service
@RequiredArgsConstructor
public class InjectorCalderaListener {

  private final InjectRepository injectRepository;
  private final InjectStatusRepository injectStatusRepository;
  private final InjectExpectationRepository injectExpectationRepository;
  private final InjectorCalderaService calderaService;
  private final AssetGroupService assetGroupService;

  @Scheduled(fixedDelay = 60000, initialDelay = 0)
  @Transactional
  public void listenAbilities() {
    // Retrieve Caldera inject not done
    List<InjectStatus> injectStatuses = this.injectStatusRepository.pendingForInjectType(CalderaContract.TYPE);
    // For each one ask for traces and status
    injectStatuses.forEach((injectStatus -> {
      String exerciseId = injectStatus.getInject().getExercise().getId();
      // Add traces and close inject if needed.
      Instant finalExecutionTime = injectStatus.getReporting().getStartTime();

      List<Asset> assets = injectStatus.getInject().getAssets();
      List<AssetGroup> assetGroups = injectStatus.getInject().getAssetGroups();
      List<Asset> totalAssets = new ArrayList<>(assetGroups.stream()
          .flatMap((assetGroup -> this.assetGroupService.assetsFromAssetGroup(assetGroup.getId()).stream()))
          .distinct()
          .toList());
      totalAssets.addAll(assets);

      String[] linkIds = injectStatus.getAsyncIds();
      List<ResultStatus> completedActions = new ArrayList<>();
      for (String linkId : linkIds) {
        try {
          ResultStatus resultStatus = this.calderaService.results(linkId);
          if (resultStatus.isComplete()) {
            completedActions.add(resultStatus);

            String currentAssetId = totalAssets.stream()
                .filter((a) -> a.getSources().containsValue(resultStatus.getPaw()))
                .findFirst()
                .map(Asset::getId)
                .orElseThrow();

            computeExpectationForAsset(exerciseId, currentAssetId, resultStatus.isFail(), resultStatus.getContent());

            // Compute biggest execution time
            if (resultStatus.getFinish().isAfter(finalExecutionTime)) {
              finalExecutionTime = resultStatus.getFinish();
            }
          }
        } catch (Exception e) {
          injectStatus.getReporting().addTrace(
              traceError("caldera", "Caldera error to execute ability", e)
          );
        }
      }

      // Compute status only if all actions are completed
      if (completedActions.size() == linkIds.length) {
        assetGroups.forEach((assetGroup -> computeExpectationForAssetGroup(exerciseId, assetGroup)));
        int failedActions = (int) completedActions.stream().filter(ResultStatus::isFail).count();
        computeInjectStatus(injectStatus, finalExecutionTime, completedActions.size(), failedActions);
        // Update related inject
        computeInject(injectStatus);
      }
    }));
  }

  // -- EXPECTATION --

  private void computeExpectationForAsset(
      @NotNull final String exerciseId,
      @NotBlank final String assetId,
      @NotNull final boolean success, // Is action failed, success for expectation
      @NotBlank final String result) {
    InjectExpectation expectation = this.injectExpectationRepository
        .findTechnicalExpectationForAsset(exerciseId, assetId);
    if (expectation != null) {
      // Not already handle
      if (expectation.getResult() == null) {
        expectation.setResult(result);
        expectation.setScore(success ? expectation.getExpectedScore() : 0);
        expectation.setUpdatedAt(Instant.now());
        this.injectExpectationRepository.save(expectation);
      }
    }
  }

  private void computeExpectationForAssetGroup(
      @NotNull final String exerciseId,
      @NotBlank final AssetGroup assetGroup) {
    InjectExpectation expectationAssetGroup = this.injectExpectationRepository
        .findTechnicalExpectationForAssetGroup(exerciseId, assetGroup.getId());
    if (expectationAssetGroup != null) {
      List<InjectExpectation> expectationsAsset = this.injectExpectationRepository
          .findTechnicalExpectationsForAssets(exerciseId, assetGroup.getAssets().stream().map(Asset::getId).toList());
      if (expectationAssetGroup.isExpectationGroup()) {
        boolean success = expectationsAsset.stream().anyMatch((e) -> e.getExpectedScore().equals(e.getScore()));
        expectationAssetGroup.setResult(success ? "VALIDATED" : "FAILED");
        expectationAssetGroup.setScore(success ? expectationAssetGroup.getExpectedScore() : 0);
      } else {
        boolean success = expectationsAsset.stream().allMatch((e) -> e.getExpectedScore().equals(e.getScore()));
        expectationAssetGroup.setResult(success ? "VALIDATED" : "FAILED");
        expectationAssetGroup.setScore(success ? expectationAssetGroup.getExpectedScore() : 0);
      }

      expectationAssetGroup.setUpdatedAt(Instant.now());
      this.injectExpectationRepository.save(expectationAssetGroup);
    }
  }

// -- INJECT STATUS --

  private void computeInjectStatus(
      @NotNull final InjectStatus injectStatus,
      @NotNull final Instant finalExecutionTime,
      final int completedActions,
      final int failedActions) {
    boolean hasError = injectStatus.getReporting().getTraces().stream()
        .anyMatch(trace -> trace.getStatus().equals(ExecutionStatus.ERROR));
    injectStatus.setName(hasError ? ExecutionStatus.ERROR.name() : ExecutionStatus.SUCCESS.name());
    injectStatus.getReporting().addTrace(
        traceInfo("caldera",
            "Caldera success to execute ability on " + (completedActions - failedActions)
                + "/" + completedActions + " asset(s)")
    );
    int executionTime = (int)
        (finalExecutionTime.toEpochMilli() - injectStatus.getReporting().getStartTime().toEpochMilli());
    injectStatus.setExecutionTime(executionTime);
    this.injectStatusRepository.save(injectStatus);
  }

  // -- INJECT --

  private void computeInject(@NotNull final InjectStatus injectStatus) {
    Inject relatedInject = injectStatus.getInject();
    relatedInject.setUpdatedAt(Instant.now());
    this.injectRepository.save(relatedInject);
  }

}
