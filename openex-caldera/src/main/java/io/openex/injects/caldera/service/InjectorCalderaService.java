package io.openex.injects.caldera.service;

import io.openex.injects.caldera.client.InjectorCalderaClient;
import io.openex.injects.caldera.client.model.Ability;
import io.openex.injects.caldera.client.model.Agent;
import io.openex.injects.caldera.client.model.Link;
import io.openex.injects.caldera.client.model.Result;
import io.openex.injects.caldera.model.ResultStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static org.springframework.util.StringUtils.hasText;

@Service
@Slf4j
@RequiredArgsConstructor
public class InjectorCalderaService {

  private final InjectorCalderaClient client;

  // -- ABILITIES --

  public List<Ability> abilities() {
    return this.client.abilities();
  }

  public void exploit(
      @NotBlank final String paw,
      @NotBlank final String abilityId) {
    this.client.exploit(paw, abilityId);
  }

  // -- LINK --

  public String linkId(
      @NotBlank final String paw,
      @NotBlank final String abilityId) {
    Agent agent = this.client.agent(paw, "links");
    // Take the last created
    Link agentLink = agent.getLinks()
        .stream()
        .filter((l) -> l.getAbility().getAbility_id().equals(abilityId))
        .max(Comparator.comparing(l -> Instant.parse(l.getDecide())))
        .orElseThrow(() -> new RuntimeException("Caldera fail to execute ability " + abilityId));
    assert paw.equals(agentLink.getPaw());
    return agentLink.getId();
  }

  public ResultStatus results(@NotBlank final String linkId) {
    ResultStatus resultStatus = new ResultStatus();
    Result result = this.client.results(linkId);
    // No result or not finish -> in progress #see caldera code
    if (Optional.ofNullable(result).map(Result::getLink).map(Link::getFinish).isEmpty()) {
      resultStatus.setComplete(false);
    } else {
      resultStatus.setComplete(true);
      Link resultLink = result.getLink();
      resultStatus.setPaw(resultLink.getPaw());
      resultStatus.setFinish(Instant.parse(resultLink.getFinish()));
      // Status == 0 -> success || Status > 0 -> failed #see caldera code
      resultStatus.setFail(resultLink.getStatus() > 0);

      // Result output can be : #see caldera code
      //    - empty if ability execution return nothing
      //    - json object with stdout & stderr if ability execution return something
      String resultOutput = result.getOutput();
      byte[] decodedBytes = Base64.getDecoder().decode(resultOutput);
      String decodedString = new String(decodedBytes);
      resultStatus.setContent(hasText(decodedString) ? decodedString : "no output to show");
    }
    return resultStatus;
  }

}
