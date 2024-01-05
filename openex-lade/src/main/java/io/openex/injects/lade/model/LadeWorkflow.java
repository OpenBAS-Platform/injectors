package io.openex.injects.lade.model;

import io.openex.database.model.ExecutionTrace;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Getter
public class LadeWorkflow {

    private final List<ExecutionTrace> traces = new ArrayList<>();

    @Setter
    private boolean done = false;

    @Setter
    private boolean fail = false;

    @Setter
    private Instant stopTime;

    public void addTrace(ExecutionTrace trace) {
        this.traces.add(trace);
    }

}
