package io.openex.injects.mastodon;

import io.openex.contract.Contract;
import io.openex.database.model.DataAttachment;
import io.openex.database.model.Document;
import io.openex.database.model.Inject;
import io.openex.database.model.InjectDocument;
import io.openex.execution.Injector;
import io.openex.execution.ExecutableInject;
import io.openex.database.model.Execution;
import io.openex.injects.mastodon.model.MastodonContent;
import io.openex.injects.mastodon.service.MastodonService;
import io.openex.model.Expectation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceSuccess;

@Component(MastodonContract.TYPE)
public class MastodonExecutor extends Injector {

    private MastodonService mastodonService;

    @Autowired
    public void setMastodonService(MastodonService mastodonService) {
        this.mastodonService = mastodonService;
    }

    @Override
    public List<Expectation> process(Execution execution, ExecutableInject injection, Contract contract) throws Exception {
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
