package io.openbas.injects.mastodon;

import io.openbas.contract.Contract;
import io.openbas.database.model.*;
import io.openbas.execution.ExecutableInject;
import io.openbas.execution.Injector;
import io.openbas.injects.mastodon.model.MastodonContent;
import io.openbas.injects.mastodon.service.MastodonService;
import io.openbas.model.Expectation;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openbas.database.model.ExecutionTrace.traceError;
import static io.openbas.database.model.ExecutionTrace.traceSuccess;

@Component(MastodonContract.TYPE)
@RequiredArgsConstructor
public class MastodonExecutor extends Injector {

    private final MastodonService mastodonService;

    @Override
    public List<Expectation> process(
        @NotNull final Execution execution,
        @NotNull final ExecutableInject injection,
        @NotNull final Contract contract) throws Exception {
        Inject inject = injection.getInject();
        MastodonContent content = contentConvert(injection, MastodonContent.class);
        String token = content.getToken();
        String status = content.buildStatus(inject.getFooter(), inject.getHeader());
        List<Document> documents = inject.getDocuments().stream()
                .filter(InjectDocument::isAttached).map(InjectDocument::getDocument).toList();
        List<DataAttachment> attachments = resolveAttachments(execution, injection, documents);
        try {
            String callResult = mastodonService.sendStatus(execution, token, status, attachments);
            String message = "Mastodon status sent (" + callResult + ")";
            execution.addTrace(traceSuccess("mastodon", message));
        } catch (Exception e) {
            execution.addTrace(traceError("mastodon", e.getMessage(), e));
        }
        return List.of();
    }
}
