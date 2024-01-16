package io.openex.injects.ssh;

import io.openex.contract.Contract;
import io.openex.database.model.Execution;
import io.openex.execution.ExecutableInject;
import io.openex.execution.Injector;
import io.openex.injects.ssh.model.SshModel;
import io.openex.injects.ssh.service.SshService;
import io.openex.model.Expectation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceSuccess;

@Component(SshContract.TYPE)
public class SshExecutor extends Injector {

    private SshService sshService;

    @Autowired
    public void setSshService(@NotNull final SshService sshService) {
        this.sshService = sshService;
    }

    @Override
    public List<Expectation> process(@NotNull final Execution execution,
                                     @NotNull final ExecutableInject injection,
                                     @NotNull final Contract contract) {
        try {
            String callResult = this.sshService.execute(contentConvert(injection, SshModel.class));
            String message = "Api request sent (" + callResult + ")";
            execution.addTrace(traceSuccess("api", message));
        } catch (Exception e) {
            execution.addTrace(traceError("api", e.getMessage(), e));
        }
        return List.of();
    }

}
