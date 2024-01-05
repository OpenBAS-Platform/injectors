package io.openex.injects.caldera.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotBlank;

@Setter
@Component
@ConfigurationProperties(prefix = "injector.caldera")
public class InjectorCalderaConfig {

  private final static String REST_V1_URI = "/api/rest";
  private final static String REST_V2_URI = "/api/v2";
  private final static String PLUGIN_ACCESS_URI = "/plugin/access";

  @Getter
  private boolean enable;

  @NotBlank
  private String url;

  @Getter
  @NotBlank
  private String apiKey;

  public String getRestApiV1Url() {
    return url + REST_V1_URI;
  }

  public String getRestApiV2Url() {
    return url + REST_V2_URI;
  }

  public String getPluginAccessApiUrl() {
    return url + PLUGIN_ACCESS_URI;
  }

}
