package io.openbas.injects.caldera;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.openbas.contract.Contract;
import io.openbas.database.model.*;
import io.openbas.execution.ExecutableInject;
import io.openbas.injects.caldera.config.InjectorCalderaConfig;
import io.openbas.injects.caldera.model.CalderaInjectContent;
import io.openbas.injects.caldera.service.InjectorCalderaService;
import io.openbas.model.inject.form.Expectation;
import io.openbas.asset.EndpointService;
import io.openbas.asset.AssetGroupService;
import jakarta.annotation.Resource;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.*;

import static io.openbas.contract.Contract.executableContract;
import static io.openbas.contract.ContractDef.contractBuilder;
import static io.openbas.database.model.Endpoint.PLATFORM_TYPE.Linux;
import static io.openbas.database.model.InjectExpectation.EXPECTATION_TYPE.TECHNICAL;
import static io.openbas.helper.SupportedLanguage.en;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class CalderaExecutorTest {

  @Autowired
  private CalderaExecutor calderaExecutor;
  @Autowired
  private CalderaContract calderaContract;
  @Autowired
  private InjectorCalderaConfig config;
  @Resource
  private ObjectMapper mapper;

  @Autowired
  private EndpointService endpointService;
  @Autowired
  private AssetGroupService assetGroupService;

  @MockBean
  private InjectorCalderaService calderaService; // Mock

  @DisplayName("Test process with endpoint")
  @Test
  void processEndpointTest() throws Exception {
    // -- PREPARE --
    Contract contract = calderaContract();

    String paw = "paw-1";
    Endpoint endpoint = createEndpoint(paw, true);

    Inject inject = new Inject();
    inject.setContract(contract.getId());
    inject.setAssets(List.of(endpoint));
    CalderaInjectContent calderaContent = calderaContent();
    inject.setContent(this.mapper.valueToTree(calderaContent));

    ExecutableInject executableInject = new ExecutableInject(true, true, inject, contract, List.of());
    Execution execution = new Execution(executableInject.isRuntime());

    // MOCK
    Mockito.when(this.calderaService.linkId(paw, contract.getId())).thenReturn("linkId1");

    // -- EXECUTE --
    List<io.openbas.model.Expectation> expectations = this.calderaExecutor
        .process(execution, executableInject, contract);
    assertEquals(1, expectations.size());

    // -- CLEAN --
    this.deleteEndpoint(endpoint.getId());
  }

  @DisplayName("Test process with asset group")
  @Test
  void processAssetGroupTest() throws Exception {
    // -- PREPARE --
    Contract contract = calderaContract();

    String paw1 = "paw-1";
    Endpoint endpointValidCollector = createEndpoint(paw1, true);
    String paw2 = "paw-2";
    Endpoint endpointNotValidCollector = createEndpoint(paw2, false);
    String paw3 = "paw-3";
    Endpoint endpointLinkIdFailed = createEndpoint(paw3, true);
    AssetGroup assetGroup = createAssetGroup(List.of(endpointValidCollector, endpointNotValidCollector, endpointLinkIdFailed));

    Inject inject = new Inject();
    inject.setContract(contract.getId());
    inject.setAssetGroups(List.of(assetGroup));
    CalderaInjectContent calderaContent = calderaContent();
    inject.setContent(this.mapper.valueToTree(calderaContent));

    ExecutableInject executableInject = new ExecutableInject(true, true, inject, contract, List.of());
    Execution execution = new Execution(executableInject.isRuntime());

    // MOCK
    Mockito.when(this.calderaService.linkId(paw1, contract.getId())).thenReturn("linkId1");
    Mockito.when(this.calderaService.linkId(paw2, contract.getId())).thenReturn("linkId2");
    Mockito.when(this.calderaService.linkId(paw3, contract.getId())).thenThrow();

    // -- EXECUTE --
    List<io.openbas.model.Expectation> expectations = this.calderaExecutor
        .process(execution, executableInject, contract);
    assertEquals(2, expectations.size()); // One for the asset group and one for the asset

    // -- CLEAN --
    this.deleteAssetGroup(assetGroup.getId());
    this.deleteEndpoint(endpointValidCollector.getId());
    this.deleteEndpoint(endpointNotValidCollector.getId());
    this.deleteEndpoint(endpointLinkIdFailed.getId());
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

  private CalderaInjectContent calderaContent() {
    CalderaInjectContent content = new CalderaInjectContent();
    List<Expectation> expectations = new ArrayList<>();
    Expectation expectation = new Expectation();
    expectation.setType(TECHNICAL);
    expectation.setName("Technical");
    expectation.setScore(10);
    expectation.setExpectationGroup(true);
    expectations.add(expectation);
    content.setExpectations(expectations);
    return content;
  }

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
    return this.endpointService.createEndpoint(endpoint);
  }

  private void deleteEndpoint(@NotBlank final String endpointId) {
    this.endpointService.deleteEndpoint(endpointId);
  }

  private AssetGroup createAssetGroup(@NotEmpty final List<Asset> assets) {
    AssetGroup assetGroup = new AssetGroup();
    String name = "Personal network";
    assetGroup.setName(name);
    assetGroup.setAssets(assets);
    return this.assetGroupService.createAssetGroup(assetGroup);
  }

  private void deleteAssetGroup(@NotBlank final String assetGroupId) {
    this.assetGroupService.deleteAssetGroup(assetGroupId);
  }

}
