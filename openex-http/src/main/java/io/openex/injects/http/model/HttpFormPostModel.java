package io.openex.injects.http.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.openex.model.PairModel;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class HttpFormPostModel {
    private String uri;

    private List<PairModel> parts;

    private boolean basicAuth;

    private String basicUser;

    private String basicPassword;

    private List<PairModel> headers;

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

    public boolean isBasicAuth() {
        return basicAuth;
    }

    public void setBasicAuth(boolean basicAuth) {
        this.basicAuth = basicAuth;
    }

    public String getBasicUser() {
        return basicUser;
    }

    public void setBasicUser(String basicUser) {
        this.basicUser = basicUser;
    }

    public String getBasicPassword() {
        return basicPassword;
    }

    public void setBasicPassword(String basicPassword) {
        this.basicPassword = basicPassword;
    }
}
