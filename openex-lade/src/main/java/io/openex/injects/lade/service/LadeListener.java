package io.openex.injects.lade.service;

import io.openex.database.model.ExecutionStatus;
import io.openex.database.model.Inject;
import io.openex.database.model.InjectStatus;
import io.openex.database.repository.InjectRepository;
import io.openex.database.repository.InjectStatusRepository;
import io.openex.injects.lade.LadeContract;
import io.openex.injects.lade.model.LadeWorkflow;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

@Service
public class LadeListener {

    private static final Logger LOGGER = Logger.getLogger(LadeListener.class.getName());
    private LadeService ladeService;

    private InjectStatusRepository injectStatusRepository;

    private InjectRepository injectRepository;

    @Autowired
    public void setInjectStatusRepository(InjectStatusRepository injectStatusRepository) {
        this.injectStatusRepository = injectStatusRepository;
    }

    @Autowired
    public void setInjectRepository(InjectRepository injectRepository) {
        this.injectRepository = injectRepository;
    }

    @Autowired
    public void setLadeService(LadeService ladeService) {
        this.ladeService = ladeService;
    }

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
                }
                injectStatus.getReporting().setTraces(workflowStatus.getTraces());
                injectStatusRepository.save(injectStatus);
                // Update related inject
                Inject relatedInject = injectStatus.getInject();
                relatedInject.setUpdatedAt(Instant.now());
                injectRepository.save(relatedInject);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e.getMessage(), e);
            }
        });
    }
}
