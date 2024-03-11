package io.openbas.injects.lade;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.openbas.database.model.Execution;
import io.openbas.database.model.Inject;
import io.openbas.execution.ExecutableInject;
import io.openbas.execution.Injector;
import io.openbas.injects.lade.service.LadeService;
import io.openbas.model.Expectation;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openbas.database.model.ExecutionTrace.traceError;
import static io.openbas.database.model.ExecutionTrace.traceInfo;

@Component(LadeContract.TYPE)
@RequiredArgsConstructor
public class LadeExecutor extends Injector {

  private final LadeService ladeService;

  @Override
  public List<Expectation> process(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection) {
    Inject inject = injection.getInjection().getInject();
    String bundleIdentifier = ""; // contract.getContext().get("bundle_identifier");
    String ladeType = ""; // contract.getContext().get("lade_type");
    ObjectNode content = inject.getContent();
    try {
      String actionWorkflowId;
      switch (ladeType) {
        case "action" -> actionWorkflowId = ladeService.executeAction(bundleIdentifier, inject.getContract(), content);
        case "scenario" ->
            actionWorkflowId = ladeService.executeScenario(bundleIdentifier, inject.getContract(), content);
        default -> throw new UnsupportedOperationException(ladeType + " not supported");
      }
      execution.setAsyncIds(new String[]{actionWorkflowId});
      String message = "Lade " + ladeType + " sent with workflow (" + actionWorkflowId + ")";
      execution.addTrace(traceInfo("lade", message));
    } catch (Exception e) {
      execution.addTrace(traceError("lade", e.getMessage(), e));
    }
    return List.of();
  }
}
