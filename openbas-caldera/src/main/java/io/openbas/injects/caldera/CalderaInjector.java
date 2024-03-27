package io.openbas.injects.caldera;

import io.openbas.service.InjectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CalderaInjector {

    private static final String CALDERA_INJECTOR_NAME = "Caldera injector";
    private static final String CALDERA_INJECTOR_ID = "b031c355-7599-4cb8-99d5-f99e0e1936a9";

    @Autowired
    public CalderaInjector(InjectorService injectorService, CalderaContract contract) {
        try {
            injectorService.register(CALDERA_INJECTOR_ID, CALDERA_INJECTOR_NAME, contract);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
