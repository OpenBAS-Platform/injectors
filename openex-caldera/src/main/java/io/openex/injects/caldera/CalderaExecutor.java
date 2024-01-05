package io.openex.injects.caldera;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.openex.contract.Contract;
import io.openex.database.model.Execution;
import io.openex.database.model.Inject;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.caldera.service.InjectorCalderaService;
import io.openex.model.Expectation;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceInfo;
import static io.openex.helper.SupportedLanguage.en;

@Component(CalderaContract.TYPE)
@RequiredArgsConstructor
public class CalderaExecutor extends Injector {

  private final InjectorCalderaService calderaService;

  @Override
  public List<Expectation> process(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection,
      @NotNull final Contract contract) {
    Inject inject = injection.getInject();
    ObjectNode content = inject.getContent();
    String endpoint = content.get("endpoint").asText();

    try {
      this.calderaService.exploit(endpoint, contract.getId());
      String linkId = this.calderaService.linkId(endpoint, contract.getId());
      execution.setAsyncId(linkId);
      String message = "Caldera execute ability " + contract.getLabel().get(en);
      execution.addTrace(traceInfo("caldera", message));
    } catch (Exception e) {
      execution.addTrace(traceError("caldera", e.getMessage(), e));
    }
    return List.of();
  }

}
