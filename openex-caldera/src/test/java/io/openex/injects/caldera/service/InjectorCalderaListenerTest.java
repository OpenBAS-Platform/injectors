package io.openex.injects.caldera.service;

import io.openex.contract.Contract;
import io.openex.database.model.*;
import io.openex.database.repository.ExerciseRepository;
import io.openex.database.repository.InjectExpectationRepository;
import io.openex.database.repository.InjectRepository;
import io.openex.database.repository.InjectStatusRepository;
import io.openex.injects.caldera.CalderaContract;
import io.openex.injects.caldera.config.InjectorCalderaConfig;
import io.openex.injects.caldera.model.ResultStatus;
import io.openex.service.AssetEndpointService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.database.model.Endpoint.PLATFORM_TYPE.Linux;
import static io.openex.database.model.ExecutionStatus.PENDING;
import static io.openex.database.model.Exercise.STATUS.RUNNING;
import static io.openex.helper.SupportedLanguage.en;
import static io.openex.injects.caldera.CalderaContract.TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class InjectorCalderaListenerTest {

  @Autowired
  private InjectorCalderaListener injectorCalderaListener;
  @Autowired
  private CalderaContract calderaContract;
  @Autowired
  private InjectorCalderaConfig config;

  @Autowired
  private ExerciseRepository exerciseRepository;
  @Autowired
  private InjectRepository injectRepository;
  @Autowired
  private InjectStatusRepository injectStatusRepository;
  @Autowired
  private InjectExpectationRepository injectExpectationRepository;

  @Autowired
  private AssetEndpointService assetEndpointService;

  @MockBean
  private InjectorCalderaService calderaService; // Mock

  @DisplayName("Test listener")
  @Test
  void listenAbilitiesTest() {
    // -- PREPARE --
    Exercise exercise = createExercise();

    String paw1 = "paw-1";
    Endpoint endpoint = createEndpoint(paw1, true);

    Inject inject = createInject(exercise, endpoint);

    InjectStatus injectStatus = createInjectStatus(inject);

    // MOCK
    ResultStatus resultStatus = new ResultStatus();
    resultStatus.setComplete(true);
    resultStatus.setPaw(paw1);
    resultStatus.setFail(false);
    resultStatus.setFinish(Instant.now().plusSeconds(60));
    Mockito.when(this.calderaService.results("linkId1")).thenReturn(resultStatus);

    // -- EXECUTE --
    this.injectorCalderaListener.listenAbilities();

    // -- ASSERT --
    InjectStatus injectStatusComputed = this.injectStatusRepository.findById(injectStatus.getId()).orElseThrow();
    assertEquals(ExecutionStatus.SUCCESS.name(), injectStatusComputed.getName());
    // Verify traces
    assertTrue(injectStatusComputed.getReporting().getTraces().stream().anyMatch((t) -> t.getMessage().contains("1/1")));

    // -- CLEAN --
    this.deleteInjectStatus(injectStatus);
    this.deleteEndpoint(endpoint);
    this.deleteInject(inject);
    this.deleteExercise(exercise);
  }

  // -- PRIVATE --

  private Contract calderaContract() {
    return executableContract(
        this.calderaContract.getConfig(),
        UUID.randomUUID().toString(),
        Map.of(en, "Fake contract"),
        contractBuilder().build()
    );
  }

  // Exercise

  private Exercise createExercise() {
    Exercise exercise = new Exercise();
    exercise.setName("Exercice name");
    exercise.setStart(Instant.now());
    exercise.setReplyTo("test@test.com");
    exercise.setStatus(RUNNING);
    return this.exerciseRepository.save(exercise);
  }

  private void deleteExercise(@NotBlank final Exercise exercise) {
    this.exerciseRepository.deleteById(exercise.getId());
  }

  // Endpoint

  private Endpoint createEndpoint(@NotBlank final String paw, boolean validCollectorId) {
    Endpoint endpoint = new Endpoint();
    endpoint.setName("Personal PC");
    endpoint.setIps(new String[]{"127.0.0.1"});
    endpoint.setHostname("hostname");
    endpoint.setPlatform(Linux);
    if (validCollectorId) {
      endpoint.setSources(new HashMap<>() {{
        put(config.getCollectorIds().stream().findFirst().orElseThrow(), paw);
      }});
    }
    return this.assetEndpointService.createEndpoint(endpoint);
  }

  private void deleteEndpoint(@NotBlank final Endpoint endpoint) {
    this.assetEndpointService.deleteEndpoint(endpoint.getId());
  }

  // Inject

  private Inject createInject(@NotNull final Exercise exercise, @NotNull final Endpoint endpoint) {
    Contract contract = calderaContract();
    Inject inject = new Inject();
    inject.setTitle("Test inject");
    inject.setType(TYPE);
    inject.setContract(contract.getId());
    inject.setDependsDuration(0L);
    inject.setExercise(exercise);
    inject.setAssets(List.of(endpoint));
    return this.injectRepository.save(inject);
  }

  private void deleteInject(@NotNull final Inject inject) {
    this.injectRepository.deleteById(inject.getId());
  }

  // Inject Status

  private InjectStatus createInjectStatus(@NotNull final Inject inject) {
    InjectStatus injectStatus = new InjectStatus();
    injectStatus.setName(PENDING.name());
    injectStatus.setInject(inject);
    injectStatus.setAsyncIds(new String[]{"linkId1"});
    Execution execution = new Execution(false);
    execution.stop();
    injectStatus.setReporting(execution);
    return injectStatusRepository.save(injectStatus);
  }

  private void deleteInjectStatus(@NotNull final InjectStatus injectStatus) {
    this.injectStatusRepository.deleteById(injectStatus.getId());
  }

}
