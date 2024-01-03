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

  @Getter
  private boolean enable;

  @NotBlank
  private String url;

  @Getter
  @NotBlank
  private String apiKey;

}
