package io.openex.injects.lade.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.openex.contract.Contract;
import io.openex.contract.ContractConfig;
import io.openex.contract.ContractDef;
import io.openex.contract.fields.ContractSelect;
import io.openex.database.model.ExecutionTrace;
import io.openex.injects.lade.config.LadeConfig;
import io.openex.injects.lade.model.LadeAuth;
import io.openex.injects.lade.model.LadeWorkflow;
import io.openex.injects.lade.model.LadeWorkzone;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.openex.contract.Contract.executableContract;
import static io.openex.contract.ContractDef.contractBuilder;
import static io.openex.contract.fields.ContractCheckbox.checkboxField;
import static io.openex.contract.fields.ContractDependencySelect.dependencySelectField;
import static io.openex.contract.fields.ContractSelect.selectFieldWithDefault;
import static io.openex.contract.fields.ContractText.textField;
import static io.openex.helper.StreamHelper.asStream;
import static io.openex.helper.SupportedLanguage.en;
import static java.text.MessageFormat.format;

@Component
public class LadeService {

    private static final Logger LOGGER = Logger.getLogger(LadeService.class.getName());
    private final HttpClient httpclient = HttpClients.createDefault();

    @Resource
    private LadeConfig config;

    @Resource
    private ObjectMapper mapper;

    @Autowired
    public void setConfig(LadeConfig config) {
        this.config = config;
    }

    // Authentication cache
    private final LadeAuth ladeAuth = new LadeAuth();

    private String ladeAuthentication() throws IOException {
        // Renew token before access token expiration.
        // Timeout is configurable, 30 minutes by default, renew 50% before timeout
        switch (ladeAuth.getTokenStatus(config.getSession())) {
            case set -> {
                return ladeAuth.getToken();
            }
            case empty -> {
                HttpPost authPost = new HttpPost(config.getUrl() + "/api/token/issue");
                authPost.setHeader("Accept", "application/json");
                authPost.setHeader("Content-type", "application/json");
                ObjectNode objectNode = mapper.createObjectNode();
                objectNode.set("username", mapper.convertValue(config.getUsername(), JsonNode.class));
                objectNode.set("password", mapper.convertValue(config.getPassword(), JsonNode.class));
                authPost.setEntity(new StringEntity(mapper.writeValueAsString(objectNode)));
                JsonNode auth = httpclient.execute(authPost, postResponse -> {
                    String body = EntityUtils.toString(postResponse.getEntity());
                    return mapper.readTree(body);
                });
                String token = auth.get("access_token").asText();
                ladeAuth.setToken(token);
                return ladeAuth.getToken();
            }
            case expire -> {
                HttpPost authPost = new HttpPost(config.getUrl() + "/api/token/renew");
                authPost.setHeader("Accept", "application/json");
                authPost.setHeader("Content-type", "application/json");
                authPost.setHeader("lade-authorization", "Bearer " + ladeAuth.getToken());
                httpclient.execute(authPost);
                ladeAuth.refreshValidity();
                return ladeAuth.getToken();
            }
            default -> throw new UnsupportedOperationException("Token status not supported");
        }
    }

    private JsonNode executeGet(String uri, boolean retry) throws IOException {
        HttpGet actionsGet = new HttpGet(config.getUrl() + uri);
        actionsGet.setHeader("lade-authorization", "Bearer " + ladeAuthentication());
        return httpclient.execute(actionsGet, getResponse -> {
            String body = EntityUtils.toString(getResponse.getEntity());
            JsonNode resultNode = mapper.readTree(body);
            // Session can be killed, so can catch 401, invalidate token and retry
            if (getResponse.getCode() == 401 && !retry) {
                ladeAuth.clear();
                return executeGet(uri, true);
            }
            if (getResponse.getCode() >= 200 && getResponse.getCode() < 300) {
                return resultNode;
            } else {
                String message = resultNode.get("message").asText();
                throw new UnsupportedOperationException(message);
            }

        });
    }

    private JsonNode executePost(String uri, ObjectNode postContent, boolean retry) throws IOException {
        HttpPost runPost = new HttpPost(config.getUrl() + uri);
        runPost.setHeader("lade-authorization", "Bearer " + ladeAuthentication());
        runPost.setHeader("Accept", "application/json");
        runPost.setHeader("Content-type", "application/json");
        runPost.setEntity(new StringEntity(mapper.writeValueAsString(postContent)));
        return httpclient.execute(runPost, postResponse -> {
            String body = EntityUtils.toString(postResponse.getEntity());
            ObjectNode resultNode = mapper.readValue(body, ObjectNode.class);
            // Session can be killed, so can catch 401, invalidate token and retry
            if (postResponse.getCode() == 401 && !retry) {
                ladeAuth.clear();
                return executePost(uri, postContent, true);
            }
            if (postResponse.getCode() >= 200 && postResponse.getCode() < 300) {
                return resultNode;
            } else {
                String message = resultNode.get("message").asText();
                throw new UnsupportedOperationException(message);
            }
        });
    }

    private Map<String, LadeWorkzone> getWorkzones() throws Exception {
        JsonNode workzones = executeGet("/api/workzones", false);
        Map<String, LadeWorkzone> zones = new HashMap<>();
        workzones.forEach(jsonNode -> {
            String name = jsonNode.get("name").asText();
            String identifier = jsonNode.get("identifier").asText();
            // FETCH HOSTS
            LadeWorkzone ladeWorkzone = new LadeWorkzone(identifier, name);
            try {
                // Fetch hosts
                JsonNode nodeHosts = executeGet("/api/workzones/" + identifier + "/hosts", false);
                Map<String, String> hostsByName = new HashMap<>();
                Map<String, String> hostsByIp = new HashMap<>();
                nodeHosts.forEach(nodeHost -> {
                    // String hostIdentifier = nodeHost.get("identifier").asText();
                    String hostname = nodeHost.get("hostname").asText();
                    String os = nodeHost.get("os").asText();
                    hostsByName.put(hostname, hostname + " (" + os + ")");
                    nodeHost.get("nics").forEach(nic -> {
                        String ip = nic.get("ip").asText();
                        hostsByIp.put(ip, hostname + " (" + os + ")" + " - " + ip);
                    });
                });
                ladeWorkzone.setHostsByName(hostsByName);
                ladeWorkzone.setHostsByIp(hostsByIp);
                // Add new built workzone
                zones.put(ladeWorkzone.getId(), ladeWorkzone);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e.getMessage(), e);
            }
        });
        return zones;
    }

    public List<Contract> buildContracts(ContractConfig contractConfig) throws Exception {
        Map<String, LadeWorkzone> workzoneContract = getWorkzones();
        Map<String, String> workzoneChoices = new HashMap<>();
        workzoneContract.values().forEach(ladeWorkzone -> workzoneChoices.put(ladeWorkzone.getId(), ladeWorkzone.getName()));
        String defaultChoice = workzoneChoices.keySet().stream().findFirst().orElseThrow();
        ContractSelect workContract = selectFieldWithDefault("workzone", "Workzone", workzoneChoices, defaultChoice);
        Map<String, Map<String, String>> workzoneHostsMap = new HashMap<>();
        workzoneContract.forEach((k, value) -> workzoneHostsMap.put(k, value.getHostsByName()));
        Map<String, Map<String, String>> workzoneHostsIps = new HashMap<>();
        workzoneContract.forEach((k, value) -> workzoneHostsIps.put(k, value.getHostsByIp()));
        List<Contract> contracts = new ArrayList<>();
        JsonNode actions = executeGet("/api/actions", false);
        Iterator<JsonNode> actionElements = actions.get("data").elements();
        actionElements.forEachRemaining(jsonNode -> {
            ContractDef builder = contractBuilder();
            builder.mandatory(workContract);
            String contractName = jsonNode.get("name").asText();
            String identifier = jsonNode.get("identifier").asText();
            String bundleIdentifier = jsonNode.get("bundle_identifier").asText();
            JsonNode categoryIdentifierNode = jsonNode.get("category_identifier");
            if (!(categoryIdentifierNode instanceof NullNode)) {
                JsonNode specs = jsonNode.get("specs");
                JsonNode source = specs.get("source");
                if (source != null) {
                    builder.mandatory(dependencySelectField("source", "Source",
                            "workzone", workzoneHostsMap));
                }
                JsonNode parameters = specs.get("parameters");
                Iterator<Map.Entry<String, JsonNode>> fields = parameters.fields();
                fields.forEachRemaining(entry -> {
                    String key = entry.getKey();
                    JsonNode parameter = entry.getValue();
                    JsonNode nameNode = parameter.get("name");
                    String name = nameNode != null ? nameNode.asText() : key;
                    List<String> types = asStream(parameter.get("types").elements()).map(JsonNode::asText).toList();
                    if (types.contains("host.nics.ip")) {
                        builder.mandatory(dependencySelectField(key, name, "workzone", workzoneHostsIps));
                    } else if (types.contains("boolean")) {
                        JsonNode defaultNode = parameter.get("default");
                        builder.optional(checkboxField(key, name, defaultNode.booleanValue()));
                    } else if (types.contains("string")) {
                        JsonNode defaultNode = parameter.get("default");
                        builder.optional(textField(key, name, defaultNode != null ? defaultNode.asText() : ""));
                    }
                });
                Contract contractInstance = executableContract(contractConfig,
                        identifier, Map.of(en, contractName), builder.build());
                contractInstance.addContext("bundle_identifier", bundleIdentifier);
                contracts.add(contractInstance);
            }
        });
        return contracts;
    }

    public String executeAction(String bundleIdentifier, String actionIdentifier, ObjectNode content) throws Exception {
        String workzone = content.get("workzone").asText();
        String uri = format("/api/workzones/{0}/bundles/{1}/actions/{2}/run", workzone, bundleIdentifier, actionIdentifier);
        // Generate object to action post
        ObjectNode postContent = mapper.createObjectNode();
        postContent.set("source", mapper.convertValue(content.get("source").asText(), JsonNode.class));
        // Remove flatten entries
        content.remove("workzone");
        content.remove("source");
        postContent.set("parameters", content);
        JsonNode postData = executePost(uri, postContent, false);
        return postData.get("workflow_id").asText();
    }

    public LadeWorkflow getWorkflowStatus(String workflowId) {
        LadeWorkflow ladeWorkflow = new LadeWorkflow();
        try {
            JsonNode workflowStatus = executeGet("/api/workflows/" + workflowId, false);
            String status = workflowStatus.get("status").asText(); // running | failed
            String workzone = workflowStatus.get("workzone_identifier").asText();
            boolean isFail = status.equals("failed");
            ladeWorkflow.setFail(isFail);
            boolean isDone = isFail || status.equals("done");
            ladeWorkflow.setDone(isDone);
            if (isDone) {
                String completeTime = workflowStatus.get("complete_time").asText();
                ladeWorkflow.setStopTime(Instant.parse(completeTime));
            }
            String uri = format("/api/workzones/{0}/workflows/{1}/events", workzone, workflowId);
            JsonNode workflowEvents = executeGet(uri, false);
            workflowEvents.forEach(workflowEvent -> {
                String eventLevel = workflowEvent.get("level").asText();
                String message = workflowEvent.get("message").asText();
                if (message.length() > 0) {
                    ExecutionTrace trace;
                    if (eventLevel.equals("error")) {
                        trace = ExecutionTrace.traceError("lade", message);
                    } else {
                        trace = ExecutionTrace.traceSuccess("lade", message);
                    }
                    ladeWorkflow.addTrace(trace);
                }
            });
            return ladeWorkflow;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
