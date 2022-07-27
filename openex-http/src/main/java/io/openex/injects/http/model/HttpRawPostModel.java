package io.openex.injects.http.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.openex.model.PairModel;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class HttpRawPostModel {
    @JsonProperty("uri")
    private String uri;

    @JsonProperty("body")
    private String body;

    @JsonProperty("headers")
    private List<PairModel> headers;

    public HttpRawPostModel() {
        // Default constructor
    }

    public HttpRawPostModel(String uri, String body, List<PairModel> headers) {
        this.uri = uri;
        this.body = body;
        this.headers = headers;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public List<PairModel> getHeaders() {
        return headers;
    }

    public void setHeaders(List<PairModel> headers) {
        this.headers = headers;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
