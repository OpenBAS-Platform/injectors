package io.openbas.injects.http;

import io.openbas.database.model.*;
import io.openbas.execution.ExecutableInject;
import io.openbas.execution.Injector;
import io.openbas.injects.http.model.HttpFormPostModel;
import io.openbas.injects.http.model.HttpGetModel;
import io.openbas.injects.http.model.HttpRawPostModel;
import io.openbas.injects.http.service.HttpService;
import io.openbas.model.Expectation;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openbas.database.model.ExecutionTrace.traceError;
import static io.openbas.database.model.ExecutionTrace.traceSuccess;
import static io.openbas.injects.http.HttpContract.*;
import static io.openbas.injects.http.service.HttpContractType.POST;
import static io.openbas.injects.http.service.HttpContractType.PUT;

@Component(HttpContract.TYPE)
@RequiredArgsConstructor
public class HttpExecutor extends Injector {

  private final HttpService apiService;

  private String processExecution(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection) throws Exception {
    Inject inject = injection.getInjection().getInject();
    List<Document> documents = inject.getDocuments().stream().filter(InjectDocument::isAttached)
        .map(InjectDocument::getDocument).toList();
    List<DataAttachment> attachments = resolveAttachments(execution, injection, documents);
    String contract = inject.getContract();
    return switch (contract) {
      case HTTP_RAW_POST_CONTRACT ->
          this.apiService.executeRaw(POST, contentConvert(injection, HttpRawPostModel.class));
      case HTTP_RAW_PUT_CONTRACT -> this.apiService.executeRaw(PUT, contentConvert(injection, HttpRawPostModel.class));
      case HTTP_FORM_POST_CONTRACT ->
          this.apiService.executeForm(POST, execution, contentConvert(injection, HttpFormPostModel.class), attachments);
      case HTTP_FORM_PUT_CONTRACT ->
          this.apiService.executeForm(PUT, execution, contentConvert(injection, HttpFormPostModel.class), attachments);
      case HTTP_GET_CONTRACT -> this.apiService.executeRestGet(contentConvert(injection, HttpGetModel.class));
      default -> throw new UnsupportedOperationException("Unknown contract " + contract);
    };
  }

  @Override
  public List<Expectation> process(
      @NotNull final Execution execution,
      @NotNull final ExecutableInject injection) {
    try {
      String callResult = processExecution(execution, injection);
      String message = "Api request sent (" + callResult + ")";
      execution.addTrace(traceSuccess("api", message));
    } catch (Exception e) {
      execution.addTrace(traceError("api", e.getMessage(), e));
    }
    return List.of();
  }
}
