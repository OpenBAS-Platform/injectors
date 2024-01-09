package io.openex.injects.caldera.service;

import io.openex.database.model.ExecutionStatus;
import io.openex.database.model.ExecutionTrace;
import io.openex.database.model.Inject;
import io.openex.database.model.InjectStatus;
import io.openex.database.repository.InjectRepository;
import io.openex.database.repository.InjectStatusRepository;
import io.openex.injects.caldera.CalderaContract;
import io.openex.injects.caldera.model.ResultStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceInfo;

@Service
@Slf4j
@RequiredArgsConstructor
public class InjectorCalderaListener {

  private final InjectRepository injectRepository;
  private final InjectStatusRepository injectStatusRepository;
  private final InjectorCalderaService calderaService;

  @Scheduled(fixedDelay = 60000, initialDelay = 0)
  public void listenAbilities() {
    // Retrieve Caldera inject not done
    List<InjectStatus> injectStatuses = this.injectStatusRepository.pendingForInjectType(CalderaContract.TYPE);
    // For each one ask for traces and status
    injectStatuses.forEach((injectStatus -> {
      // Add traces and close inject if needed.
      Instant finalExecutionTime = injectStatus.getReporting().getStartTime();
      String[] asyncIds = injectStatus.getAsyncIds();
      for (String asyncId : asyncIds) {
        try {
          ResultStatus resultStatus = this.calderaService.results(asyncId);
          if (resultStatus.isComplete()) {
            if (resultStatus.isFail()) {
              injectStatus.getReporting().addTrace(
                  traceError(asyncId, "Result on endpoint " + resultStatus.getPaw() + " \n" + resultStatus.getContent())
              );
            } else {
              injectStatus.getReporting().addTrace(
                  traceInfo(asyncId, "Result on endpoint " + resultStatus.getPaw() + " \n" + resultStatus.getContent())
              );
            }

            // Compute biggest execution time
            if (resultStatus.getFinish().isAfter(finalExecutionTime)) {
              finalExecutionTime = resultStatus.getFinish();
            }
          }
        } catch (Exception e) {
          log.error(e.getMessage(), e);
        }
      }
      // Compute status only if all actions are completed
      computeInjectStatus(injectStatus);
      int executionTime = (int) (finalExecutionTime.toEpochMilli() - injectStatus.getReporting().getStartTime().toEpochMilli());
      injectStatus.setExecutionTime(executionTime);
      this.injectStatusRepository.save(injectStatus);
      // Update related inject
      Inject relatedInject = injectStatus.getInject();
      relatedInject.setUpdatedAt(Instant.now());
      this.injectRepository.save(relatedInject);
    }));
  }

  private void computeInjectStatus(@NotNull final InjectStatus injectStatus) {
    List<String> asyncIds = Arrays.asList(injectStatus.getAsyncIds());
    List<ExecutionTrace> traces = injectStatus.getReporting()
        .getTraces()
        .stream()
        .filter((e) -> asyncIds.contains(e.getIdentifier()))
        .toList();
    // If all actions completed -> compute inject status
    if (traces.size() == asyncIds.size()) {
      if (traces.stream().anyMatch((e) -> e.getStatus().equals(ExecutionStatus.ERROR))) {
        injectStatus.setName(ExecutionStatus.ERROR.name());
      } else {
        injectStatus.setName(ExecutionStatus.SUCCESS.name());
      }
    }
  }

}
