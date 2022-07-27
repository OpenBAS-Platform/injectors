package io.openex.injects.http.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.openex.model.PairModel;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class HttpFormPostModel {
    @JsonProperty("uri")
    private String uri;

    @JsonProperty("parts")
    private List<PairModel> parts;

    @JsonProperty("headers")
    private List<PairModel> headers;

    public HttpFormPostModel() {
        // Default constructor
    }

    public HttpFormPostModel(String uri, List<PairModel> parts, List<PairModel> headers) {
        this.uri = uri;
        this.parts = parts;
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

    public List<PairModel> getParts() {
        return parts;
    }

    public void setParts(List<PairModel> parts) {
        this.parts = parts;
    }
}
