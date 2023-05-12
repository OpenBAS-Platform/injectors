package io.openex.injects.ssh.service;

import io.openex.injects.ssh.model.SshModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SshServiceTest {

    private final SshService sshService = new SshService();

    @Test
    void executeTest() {
        SshModel sshModel = new SshModel();
        sshModel.setUsername("romu");
        sshModel.setPassword("EmmQUypkSVGHmw");
        sshModel.setHost("tty.sdf.org");
        sshModel.setCommand("ls");
        String result = this.sshService.execute(sshModel);

        assertNotNull(result);
    }

}
