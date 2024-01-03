package io.openex.injects.caldera.client;

import io.openex.injects.caldera.config.InjectorCalderaConfig;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CalderaClient {

  private static final String KEY_HEADER = "KEY";

  private final CloseableHttpClient httpClient = HttpClientBuilder.create().build();
  private final InjectorCalderaConfig config;

}
