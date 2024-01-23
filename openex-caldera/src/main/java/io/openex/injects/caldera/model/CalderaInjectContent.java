package io.openex.injects.caldera.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.openex.model.inject.form.Expectation;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class CalderaInjectContent {

  @JsonProperty("obfuscator")
  private String obfuscator;

  @JsonProperty("endpoint")
  private String endpoint;

  @JsonProperty("assetgroup")
  private String assetgroup;

  @JsonProperty("expectations")
  private List<Expectation> expectations = new ArrayList<>();

}
