package io.openex.injects.lade.service;

import io.openex.database.model.ExecutionStatus;
import io.openex.database.model.InjectStatus;
import io.openex.database.repository.InjectStatusRepository;
import io.openex.injects.lade.LadeContract;
import io.openex.injects.lade.model.LadeWorkflow;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LadeListener {

    private LadeService ladeService;

    private InjectStatusRepository injectStatusRepository;

    @Autowired
    public void setInjectStatusRepository(InjectStatusRepository injectStatusRepository) {
        this.injectStatusRepository = injectStatusRepository;
    }

    @Autowired
    public void setLadeService(LadeService ladeService) {
        this.ladeService = ladeService;
    }

    // Session can be killed, so can catch 401, regenerate token in this case.
    // 01. Recovery
    // /api/workflows/id -> Get status only
    // /api/workflows/id/events -> Get workflow events

    // 02. Runtime
    // Creation action -> ID A
    // Monitor ID A -> /api/events (SSE) only live.

    @Scheduled(fixedDelay = 15000, initialDelay = 0)
    public void listenWorkflows() {
        // Get all lade inject with workflow_id that are not done yet
        List<InjectStatus> injectStatuses = injectStatusRepository.pendingForInjectType(LadeContract.TYPE);
        // For each workflow ask for traces and status
        injectStatuses.forEach(injectStatus -> {
            String asyncId = injectStatus.getAsyncId();
            // Add traces and close inject if needed.
            try {
                LadeWorkflow workflowStatus = ladeService.getWorkflowStatus(asyncId);
                if (workflowStatus.isDone()) {
                    String name = workflowStatus.isFail() ? ExecutionStatus.ERROR.name() : ExecutionStatus.SUCCESS.name();
                    injectStatus.setName(name);
                    int executionTime = (int) (workflowStatus.getStopTime().toEpochMilli()
                            - injectStatus.getReporting().getStartTime().toEpochMilli());
                    injectStatus.setExecutionTime(executionTime);
                    injectStatusRepository.save(injectStatus);
                }
            } catch (Exception e) {
                e.printStackTrace();
                // TODO
            }
            // injectStatus.set
            // injectStatus.setExecutionTime(execution.getExecutionTime());
            // injectStatus.setName(execution.getStatus().name());
            // injectStatus.setReporting(execution);
            // injectStatusRepository.save(injectStatus);
        });
    }
}
