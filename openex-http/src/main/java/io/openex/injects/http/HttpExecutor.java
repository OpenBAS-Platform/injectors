package io.openex.injects.http;

import io.openex.contract.Contract;
import io.openex.database.model.Execution;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.http.model.HttpGetModel;
import io.openex.injects.http.model.HttpPostModel;
import io.openex.injects.http.service.HttpService;
import io.openex.model.Expectation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceSuccess;
import static io.openex.injects.http.HttpContract.HTTP_GET_CONTRACT;
import static io.openex.injects.http.HttpContract.HTTP_POST_CONTRACT;

@Component(HttpContract.TYPE)
public class HttpExecutor extends Injector {

    private HttpService apiService;

    @Autowired
    public void setApiService(HttpService apiService) {
        this.apiService = apiService;
    }

    private String processExecution(ExecutableInject injection, Contract contract) throws Exception {
        return switch (contract.getId()) {
            case HTTP_POST_CONTRACT -> apiService.executeRestPost(contentConvert(injection, HttpPostModel.class));
            case HTTP_GET_CONTRACT -> apiService.executeRestGet(contentConvert(injection, HttpGetModel.class));
            default -> throw new UnsupportedOperationException("Unknown contract " + contract.getId());
        };
    }

    @Override
    public List<Expectation> process(Execution execution, ExecutableInject injection, Contract contract) {
        try {
            String callResult = processExecution(injection, contract);
            String message = "Api request sent (" + callResult + ")";
            execution.addTrace(traceSuccess("api", message));
        } catch (Exception e) {
            execution.addTrace(traceError("api", e.getMessage(), e));
        }
        return List.of();
    }
}
