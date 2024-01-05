package io.openex.injects.caldera.service;

import io.openex.database.model.ExecutionStatus;
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

import java.time.Instant;
import java.util.List;

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
      try {
        ResultStatus resultStatus = this.calderaService.results(injectStatus.getAsyncId());
        if (resultStatus.isComplete()) {
          String name = resultStatus.isFail() ? ExecutionStatus.SUCCESS.name() : ExecutionStatus.ERROR.name();
          injectStatus.setName(name);
          int executionTime = (int) (resultStatus.getFinish().toEpochMilli()
              - injectStatus.getReporting().getStartTime().toEpochMilli());
          injectStatus.setExecutionTime(executionTime);
          injectStatus.getReporting().addTrace(traceInfo("result", resultStatus.getContent()));
          this.injectStatusRepository.save(injectStatus);
          // Update related inject
          Inject relatedInject = injectStatus.getInject();
          relatedInject.setUpdatedAt(Instant.now());
          this.injectRepository.save(relatedInject);
        }
      } catch (Exception e) {
        log.error(e.getMessage(), e);
      }
    }));
  }

}
