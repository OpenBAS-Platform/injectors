package io.openex.injects.http.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.openex.model.PairModel;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class HttpFormPostModel {

  private String uri;

  private List<PairModel> parts;

  private boolean basicAuth;

  private String basicUser;

  private String basicPassword;

  private List<PairModel> headers;

}
