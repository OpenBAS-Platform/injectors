package io.openex.injects.caldera.model;

import lombok.Data;

import java.time.Instant;

@Data
public class ResultStatus {

  private boolean complete;
  private boolean fail;
  private Instant finish;
  private String content;

}
