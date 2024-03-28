package io.openbas.injects.mastodon;

import io.openbas.service.InjectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class MastodonInjector {

    private static final String MASTODON_INJECTOR_NAME = "Mastodon injector";
    private static final String MASTODON_INJECTOR_ID = "b031c355-7599-4cb8-99d5-f99e0e1938a9";

    @Autowired
    public MastodonInjector(InjectorService injectorService, MastodonContract contract) {
        try {
            injectorService.register(MASTODON_INJECTOR_ID, MASTODON_INJECTOR_NAME, contract);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
