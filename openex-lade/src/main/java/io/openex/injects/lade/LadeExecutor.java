package io.openex.injects.lade;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.openex.contract.Contract;
import io.openex.database.model.Inject;
import io.openex.execution.Injector;
import io.openex.execution.ExecutableInject;
import io.openex.database.model.Execution;
import io.openex.injects.lade.service.LadeService;
import io.openex.model.Expectation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceSuccess;

@Component(LadeContract.TYPE)
public class LadeExecutor extends Injector {

    private LadeService ladeService;

    @Autowired
    public void setLadeService(LadeService ladeService) {
        this.ladeService = ladeService;
    }

    @Override
    public List<Expectation> process(Execution execution, ExecutableInject injection, Contract contract) {
        Inject inject = injection.getInject();
        String bundleIdentifier = contract.getContext().get("bundle_identifier");
        ObjectNode content = inject.getContent();
        try {
            String callResult = ladeService.executeAction(bundleIdentifier, inject.getContract(), content);
            String message = "Lade action sent with workflow (" + callResult + ")";
            execution.addTrace(traceSuccess("lade", message));
        } catch (Exception e) {
            execution.addTrace(traceError("lade", e.getMessage(), e));
        }
        return List.of();
    }
}
