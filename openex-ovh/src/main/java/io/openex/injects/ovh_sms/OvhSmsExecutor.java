package io.openex.injects.ovh_sms;

import io.openex.contract.Contract;
import io.openex.database.model.Inject;
import io.openex.execution.Injector;
import io.openex.execution.ExecutableInject;
import io.openex.database.model.Execution;
import io.openex.execution.ExecutionContext;
import io.openex.execution.ProtectUser;
import io.openex.injects.ovh_sms.model.OvhSmsContent;
import io.openex.injects.ovh_sms.service.OvhSmsService;
import io.openex.model.Expectation;
import io.openex.model.expectation.ManualExpectation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.List;

import static io.openex.database.model.ExecutionTrace.traceError;
import static io.openex.database.model.ExecutionTrace.traceSuccess;

@Component(OvhSmsContract.TYPE)
public class OvhSmsExecutor extends Injector {

  private OvhSmsService smsService;

  @Autowired
  public void setSmsService(OvhSmsService smsService) {
    this.smsService = smsService;
  }

  @Override
  public List<Expectation> process(Execution execution, ExecutableInject injection, Contract contract)
      throws Exception {
    Inject inject = injection.getInject();
    OvhSmsContent content = contentConvert(injection, OvhSmsContent.class);
    String smsMessage = content.buildMessage(inject.getFooter(), inject.getHeader());
    List<ExecutionContext> users = injection.getUsers();
    if (users.size() == 0) {
      throw new UnsupportedOperationException("Sms needs at least one user");
    }
    users.stream().parallel().forEach(context -> {
      ProtectUser user = context.getUser();
      String phone = user.getPhone();
      String email = user.getEmail();
      if (!StringUtils.hasLength(phone)) {
        String message = "Sms fail for " + email + ": no phone number";
        execution.addTrace(traceError(user.getId(), message));
      } else {
        try {
          String callResult = smsService.sendSms(context, phone, smsMessage);
          String message = "Sms sent to " + email + " through " + phone + " (" + callResult + ")";
          execution.addTrace(traceSuccess(user.getId(), message));
        } catch (Exception e) {
          execution.addTrace(traceError(user.getId(), e.getMessage(), e));
        }
      }
    });
    return switch (content.getExpectationType()) {
      case "manual" -> List.of(new ManualExpectation(content.getExpectationScore()));
      default -> List.of();
    };
  }
}
