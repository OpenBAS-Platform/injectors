package io.openbas.injects.lade;

import io.openbas.service.InjectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class LadeInjector {

    private static final String LADE_INJECTOR_NAME = "OVH SMS injector";
    private static final String LADE_INJECTOR_ID = "b031c355-7599-4cb8-99d5-f99e0e1939a9";

    @Autowired
    public LadeInjector(InjectorService injectorService, LadeContract contract) {
        try {
            injectorService.register(LADE_INJECTOR_ID, LADE_INJECTOR_NAME, contract);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
