package io.openex.injects.http.service;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openex.database.model.DataAttachment;
import io.openex.database.model.Execution;
import io.openex.injects.http.model.HttpFormPostModel;
import io.openex.injects.http.model.HttpGetModel;
import io.openex.injects.http.model.HttpRawPostModel;
import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

import static io.openex.contract.fields.ContractTuple.FILE_PREFIX;
import static io.openex.database.model.ExecutionTrace.traceError;
import static java.nio.charset.StandardCharsets.UTF_8;

@Component
public class HttpService {
    private static final Logger LOGGER = Logger.getLogger(HttpService.class.getName());
    private final CloseableHttpClient httpclient = HttpClients.createDefault();

    @Resource
    protected ObjectMapper mapper;

    private String executeHttp(ClassicHttpRequest request) throws IOException, ParseException {
        CloseableHttpResponse response = httpclient.execute(request);
        int status = response.getCode();
        String responseData = EntityUtils.toString(response.getEntity());
        if (status >= HttpStatus.SC_SUCCESS && status < HttpStatus.SC_REDIRECTION) {
            return responseData;
        } else {
            throw new ClientProtocolException("Unexpected response: " + responseData);
        }
    }

    private boolean isJsonText(String json) {
        try {
            mapper.readTree(json);
        } catch (JacksonException e) {
            return false;
        }
        return true;
    }

    public String executeForm(HttpContractType type, Execution execution, HttpFormPostModel post, List<DataAttachment> attachments) throws IOException, ParseException {
        HttpUriRequestBase httpPost = type.equals(HttpContractType.POST) ?
                new HttpPost(post.getUri()) : new HttpPut(post.getUri());
        post.getHeaders().forEach(apiHeader -> httpPost.setHeader(apiHeader.getKey(), apiHeader.getValue()));
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.setCharset(UTF_8);
        post.getParts().forEach(pair -> {
            String val = pair.getValue();
            if (val.startsWith(FILE_PREFIX)) {  // If related to attachment
                String fileId = val.substring(val.indexOf(FILE_PREFIX) + FILE_PREFIX.length());
                Optional<DataAttachment> attachmentOptional = attachments.stream().filter(a -> a.id().equals(fileId)).findFirst();
                if (attachmentOptional.isPresent()) {
                    DataAttachment file = attachmentOptional.get();
                    builder.addBinaryBody(pair.getKey(), file.data(), ContentType.parse(file.contentType()), file.name());
                } else {
                    String message = "Error finding attachment for " + fileId + " when Sending form post";
                    execution.addTrace(traceError("http", message));
                }
            } else {
                ContentType contentType = isJsonText(val) ? ContentType.APPLICATION_JSON : ContentType.TEXT_PLAIN;
                builder.addTextBody(pair.getKey(), val, ContentType.create(contentType.getMimeType(), UTF_8));
            }
        });
        httpPost.setEntity(builder.build());
        LOGGER.info("Sending form " + type.name() + " request to " + post.getUri());
        return executeHttp(httpPost);
    }

    public String executeRaw(HttpContractType type, HttpRawPostModel post) throws IOException, ParseException {
        HttpUriRequestBase httpPost = type.equals(HttpContractType.POST) ?
                new HttpPost(post.getUri()) : new HttpPut(post.getUri());
        post.getHeaders().forEach(apiHeader -> httpPost.setHeader(apiHeader.getKey(), apiHeader.getValue()));
        ContentType contentType = isJsonText(post.getBody()) ? ContentType.APPLICATION_JSON : ContentType.TEXT_PLAIN;
        httpPost.setEntity(new StringEntity(post.getBody(), ContentType.create(contentType.getMimeType(), UTF_8)));
        LOGGER.info("Sending raw " + type.name() + " request to " + post.getUri());
        return executeHttp(httpPost);
    }

    public String executeRestGet(HttpGetModel get) throws IOException, ParseException {
        HttpGet httpGet = new HttpGet(get.getUri());
        get.getHeaders().forEach(apiHeader -> httpGet.setHeader(apiHeader.getKey(), apiHeader.getValue()));
        LOGGER.info("Sending get request to " + get.getUri());
        return executeHttp(httpGet);
    }
}
