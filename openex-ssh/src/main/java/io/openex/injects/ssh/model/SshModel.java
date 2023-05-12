package io.openex.injects.ssh.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SshModel {

    @NotNull
    private String username;
    @NotNull
    private String password;
    @NotNull
    private String host;
    @NotNull
    private int port = 22;
    @NotNull
    private String command;

}
