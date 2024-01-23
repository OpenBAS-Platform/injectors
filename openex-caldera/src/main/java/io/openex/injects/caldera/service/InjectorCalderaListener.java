package io.openex.injects.caldera.service;

import io.openex.database.model.*;
import io.openex.database.repository.InjectExpectationRepository;
import io.openex.database.repository.InjectRepository;
import io.openex.database.repository.InjectStatusRepository;
import io.openex.injects.caldera.CalderaContract;
import io.openex.injects.caldera.model.ResultStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceInfo;

@Service
@RequiredArgsConstructor
public class InjectorCalderaListener {

  private final InjectRepository injectRepository;
  private final InjectStatusRepository injectStatusRepository;
  private final InjectExpectationRepository injectExpectationRepository;
  private final InjectorCalderaService calderaService;

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
      String[] linkIds = injectStatus.getAsyncIds();
      List<ResultStatus> completedActions = new ArrayList<>();
      for (String linkId : linkIds) {
        try {
          ResultStatus resultStatus = this.calderaService.results(linkId);
          if (resultStatus.isComplete()) {
            completedActions.add(resultStatus);

            String currentAssetId = assets.stream()
                .filter((a) -> a.getSources().containsValue(resultStatus.getPaw()))
                .findFirst()
                .map(Asset::getId)
                .orElseThrow();

            boolean computed = this.injectExpectationRepository
                .computedTechnicalExpectation(exerciseId, currentAssetId);

            // Already handle ?
            if (!computed) {
              computeExpectation(exerciseId, currentAssetId, resultStatus.isFail(), resultStatus.getContent(), assets);
            }

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
        int failedActions = (int) completedActions.stream().filter(ResultStatus::isFail).count();
        computeInjectStatus(injectStatus, finalExecutionTime, completedActions.size(), failedActions);
        // Update related inject
        computeInject(injectStatus);
      }
    }));
  }

  // -- EXPECTATION --

  private void computeExpectation(
      @NotNull final String exerciseId,
      @NotBlank final String assetId,
      @NotNull final boolean success, // Is action failed, success for expectation
      @NotBlank final String result,
      @NotEmpty final List<Asset> assets) {
    InjectExpectation expectation = this.injectExpectationRepository
        .findTechnicalExpectation(exerciseId, assetId);
    if (expectation != null) {
      // If not a group or not already handle by group mechanism
      if (!(expectation.isExpectationGroup() && expectation.getResult() != null)) {
        expectation.setResult(result);
        expectation.setScore(success ? expectation.getExpectedScore() : 0);
        expectation.setUpdatedAt(Instant.now());
        this.injectExpectationRepository.save(expectation);
        // If group & failed -> every expectation failed
        if (expectation.isExpectationGroup() && !success) {
          List<InjectExpectation> expectations = this.injectExpectationRepository
              .findTechnicalExpectations(exerciseId, assets.stream().map(Asset::getId).toList());
          expectations.forEach((e) -> {
            e.setResult(result);
            e.setScore(0);
            e.setUpdatedAt(Instant.now());
          });
          this.injectExpectationRepository.saveAll(expectations);
        }
      }
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
