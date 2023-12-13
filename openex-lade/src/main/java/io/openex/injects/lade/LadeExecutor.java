package io.openex.injects.lade;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.openex.contract.Contract;
import io.openex.database.model.Execution;
import io.openex.database.model.Inject;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.lade.service.LadeService;
import io.openex.model.Expectation;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceInfo;

@Component(LadeContract.TYPE)
@RequiredArgsConstructor
public class LadeExecutor extends Injector {

  private final LadeService ladeService;

  @Override
  public List<Expectation> process(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection,
      @NotNull final Contract contract) {
    Inject inject = injection.getInject();
    String bundleIdentifier = contract.getContext().get("bundle_identifier");
    String ladeType = contract.getContext().get("lade_type");
    ObjectNode content = inject.getContent();
    try {
      String actionWorkflowId;
      switch (ladeType) {
        case "action" -> actionWorkflowId = ladeService.executeAction(bundleIdentifier, inject.getContract(), content);
        case "scenario" ->
            actionWorkflowId = ladeService.executeScenario(bundleIdentifier, inject.getContract(), content);
        default -> throw new UnsupportedOperationException(ladeType + " not supported");
      }
      execution.setAsyncId(actionWorkflowId);
      String message = "Lade " + ladeType + " sent with workflow (" + actionWorkflowId + ")";
      execution.addTrace(traceInfo("lade", message));
    } catch (Exception e) {
      execution.addTrace(traceError("lade", e.getMessage(), e));
    }
    return List.of();
  }
}
