package io.openex.injects.lade.model;

import java.time.Instant;

public class LadeWorkflow {

    private boolean done = false;

    private boolean fail = false;

    private Instant stopTime;

    public Instant getStopTime() {
        return stopTime;
    }

    public void setStopTime(Instant stopTime) {
        this.stopTime = stopTime;
    }

    public boolean isDone() {
        return done;
    }

    public void setDone(boolean done) {
        this.done = done;
    }

    public boolean isFail() {
        return fail;
    }

    public void setFail(boolean fail) {
        this.fail = fail;
    }
}
