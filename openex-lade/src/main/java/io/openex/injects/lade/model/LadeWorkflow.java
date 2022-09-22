package io.openex.injects.lade.model;

import io.openex.database.model.ExecutionTrace;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class LadeWorkflow {

    private final List<ExecutionTrace> traces = new ArrayList<>();

    private boolean done = false;

    private boolean fail = false;

    private Instant stopTime;

    public void addTrace(ExecutionTrace trace) {
        this.traces.add(trace);
    }

    public List<ExecutionTrace> getTraces() {
        return traces;
    }

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
