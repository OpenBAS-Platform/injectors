package io.openex.injects.lade.service;

import io.openex.database.model.ExecutionStatus;
import io.openex.database.model.Inject;
import io.openex.database.model.InjectStatus;
import io.openex.database.repository.InjectRepository;
import io.openex.database.repository.InjectStatusRepository;
import io.openex.injects.lade.LadeContract;
import io.openex.injects.lade.model.LadeWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class LadeListener {

  private final InjectRepository injectRepository;
  private final InjectStatusRepository injectStatusRepository;
  private final LadeService ladeService;

  @Scheduled(fixedDelay = 15000, initialDelay = 0)
  public void listenWorkflows() {
    // Get all lade inject with workflow_id that are not done yet
    List<InjectStatus> injectStatuses = this.injectStatusRepository.pendingForInjectType(LadeContract.TYPE);
    // For each workflow ask for traces and status
    injectStatuses.forEach(injectStatus -> {
      // Add traces and close inject if needed.
      String asyncId = Arrays.stream(injectStatus.getAsyncIds())
          .findFirst()
          .orElse(null); // Lade handle only one asyncID for now
      try {
        LadeWorkflow workflowStatus = this.ladeService.getWorkflowStatus(asyncId);
        if (workflowStatus.isDone()) {
          String name = workflowStatus.isFail() ? ExecutionStatus.ERROR.name() : ExecutionStatus.SUCCESS.name();
          injectStatus.setName(name);
          int executionTime = (int) (workflowStatus.getStopTime().toEpochMilli()
              - injectStatus.getReporting().getStartTime().toEpochMilli());
          injectStatus.setExecutionTime(executionTime);
        }
        injectStatus.getReporting().setTraces(workflowStatus.getTraces());
        this.injectStatusRepository.save(injectStatus);
        // Update related inject
        Inject relatedInject = injectStatus.getInject();
        relatedInject.setUpdatedAt(Instant.now());
        this.injectRepository.save(relatedInject);
      } catch (Exception e) {
        log.error(e.getMessage(), e);
      }
    });
  }
}
