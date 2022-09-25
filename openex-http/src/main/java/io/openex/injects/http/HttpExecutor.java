package io.openex.injects.http;

import io.openex.contract.Contract;
import io.openex.database.model.DataAttachment;
import io.openex.database.model.Document;
import io.openex.database.model.Execution;
import io.openex.database.model.InjectDocument;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.http.model.HttpFormPostModel;
import io.openex.injects.http.model.HttpGetModel;
import io.openex.injects.http.model.HttpRawPostModel;
import io.openex.injects.http.service.HttpService;
import io.openex.model.Expectation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceSuccess;
import static io.openex.injects.http.HttpContract.*;
import static io.openex.injects.http.service.HttpContractType.POST;
import static io.openex.injects.http.service.HttpContractType.PUT;

@Component(HttpContract.TYPE)
public class HttpExecutor extends Injector {

    private HttpService apiService;

    @Autowired
    public void setApiService(HttpService apiService) {
        this.apiService = apiService;
    }

    private String processExecution(Execution execution, ExecutableInject injection, Contract contract) throws Exception {
        List<Document> documents = injection.getInject().getDocuments().stream().filter(InjectDocument::isAttached)
                .map(InjectDocument::getDocument).toList();
        List<DataAttachment> attachments = resolveAttachments(execution, injection, documents);
        return switch (contract.getId()) {
            case HTTP_RAW_POST_CONTRACT ->
                    apiService.executeRaw(POST, contentConvert(injection, HttpRawPostModel.class));
            case HTTP_RAW_PUT_CONTRACT ->
                    apiService.executeRaw(PUT, contentConvert(injection, HttpRawPostModel.class));
            case HTTP_FORM_POST_CONTRACT ->
                    apiService.executeForm(POST, execution, contentConvert(injection, HttpFormPostModel.class), attachments);
            case HTTP_FORM_PUT_CONTRACT ->
                    apiService.executeForm(PUT, execution, contentConvert(injection, HttpFormPostModel.class), attachments);
            case HTTP_GET_CONTRACT ->
                    apiService.executeRestGet(contentConvert(injection, HttpGetModel.class));
            default -> throw new UnsupportedOperationException("Unknown contract " + contract.getId());
        };
    }

    @Override
    public List<Expectation> process(Execution execution, ExecutableInject injection, Contract contract) {
        try {
            String callResult = processExecution(execution, injection, contract);
            String message = "Api request sent (" + callResult + ")";
            execution.addTrace(traceSuccess("api", message));
        } catch (Exception e) {
            execution.addTrace(traceError("api", e.getMessage(), e));
        }
        return List.of();
    }
}
