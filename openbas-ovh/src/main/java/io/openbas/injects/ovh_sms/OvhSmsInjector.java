package io.openbas.injects.ovh_sms;

import io.openbas.service.InjectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class OvhSmsInjector {

    private static final String OVH_SMS_INJECTOR_NAME = "OVH SMS injector";
    private static final String OVH_SMS_INJECTOR_ID = "b031c355-7599-4cb8-99d5-f99e0e1937a9";

    @Autowired
    public OvhSmsInjector(InjectorService injectorService, OvhSmsContract contract) {
        try {
            injectorService.register(OVH_SMS_INJECTOR_ID, OVH_SMS_INJECTOR_NAME, contract);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
