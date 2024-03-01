package io.openbas.injects.http.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.openbas.model.PairModel;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class HttpGetModel {

  private String uri;

  private boolean basicAuth;

  private String basicUser;

  private String basicPassword;

  private List<PairModel> headers;

}
