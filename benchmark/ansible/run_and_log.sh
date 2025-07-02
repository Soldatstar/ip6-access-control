#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error
set -u
# Pipelines fail if any command fails, not just the last one
set -o pipefail

# --- Configuration ---
RUNS=500
# Define all benchmark targets in an array
BENCHMARKS=("run" "run2" "run3")
AVERAGE_LOG="average_times.log"

# --- Helper Function to Run a Full Benchmark Suite ---
run_benchmark() {
    local make_target=$1
    local times_log="${make_target}_times.log"
    local supervisor_log="${make_target}_supervisor.log"

    echo "===================================================="
    echo "--- Starting Benchmark for 'make ${make_target}'"
    echo "===================================================="

    # 1. Start the supervisor for this benchmark suite
    echo "Starting supervisor ('make ut') in background..."
    make ut > "$supervisor_log" 2>&1 &
    local supervisor_pid=$!

    # Give the supervisor a moment to initialize.
    # A more robust method could be to grep supervisor_log for a "ready" message.
    echo "Waiting for supervisor (PID: ${supervisor_pid}) to be ready..."
    sleep 3

    # 2. Run the benchmark N times
    echo "Running 'make ${make_target}' ${RUNS} times..."
    # Ensure the log file is empty before we start
    > "$times_log"

    for i in $(seq 1 $RUNS); do
        # Use printf for neat, single-line progress updates
        printf "  Run #%-3d... " "$i"

        # Run the command, redirecting stderr to stdout to capture the supervisor's output
        local output
        output=$(make "${make_target}" 2>&1)

        # Extract just the numeric value of the execution time
        # The 'grep' finds the line, and 'awk' prints the 5th word on that line.
        local time_value
        time_value=$(echo "$output" | grep "Total execution time:" | awk '{print $5}')

        if [[ -n "$time_value" ]]; then
            echo "$time_value" >> "$times_log"
            echo "OK (${time_value}ms)"
        else
            echo "FAIL (Could not extract execution time from output)"
        fi
    done

    # 3. Clean up the supervisor process
    echo "Stopping supervisor (PID ${supervisor_pid})..."
    # Using 'kill' and '|| true' prevents the script from exiting if the process is already gone
    kill "$supervisor_pid" || true
    # A small pause to allow the OS to clean up the process fully
    sleep 1

    # 4. Calculate and report the average3
    local total_runs_logged
    total_runs_logged=$(wc -l < "$times_log") # Count lines in the log file

    if [[ "$total_runs_logged" -gt 0 ]]; then
        # Use awk to sum all values in the file and divide by the number of lines (NR)
        local avg_time
        avg_time=$(awk '{s+=$1} END {print s/NR}' "$times_log")

        local avg_line="[${make_target}] --> Average execution time over ${total_runs_logged} runs: ${avg_time} ms."
        echo
        echo "Benchmark for 'make ${make_target}' complete."
        echo "$avg_line"
        echo "    (Raw times logged in '${times_log}')"
        # Save the average line to the summary file
        echo "$avg_line" >> "$AVERAGE_LOG"
    else
        echo
        echo "Benchmark for 'make ${make_target}' FAILED. No successful runs were recorded."
    fi
    echo
}


# --- Main Script Execution ---
# Clear the summary file before starting benchmarks
> "$AVERAGE_LOG"

# Loop through the defined benchmarks and run the function for each
for benchmark_target in "${BENCHMARKS[@]}"; do
    run_benchmark "$benchmark_target"
done

echo "===================================================="
echo "All benchmarks have been completed."
echo "===================================================="

# --- Additional Hyperfine and Binary Benchmarks ---
echo "Running extra benchmarks with hyperfine and direct execution..."

# 1. hyperfine for ./demo/child-process
hyperfine ./demo/child-process -N --warmup 5 --runs $RUNS > hyperfine_child-process.log

# 2. hyperfine for ./demo/normal-file
hyperfine ./demo/normal-file -N --warmup 5 --runs $RUNS > normal-file.log

# 3. hyperfine for ./demo/communication
hyperfine ./demo/communication -N --warmup 5 --runs $RUNS > communication.log

echo "Extra benchmarks complete. Results saved to:"
echo "  hyperfine_child-process.log"
echo "  normal-file.log"
echo "  communication.log"

# --- Append hyperfine results to summary file ---
parse_hyperfine_mean() {
    # $1: log file, $2: label
    local mean_line
    mean_line=$(grep -m1 'Time (mean' "$1")
    if [[ -n "$mean_line" ]]; then
        # Extract the mean and stddev (e.g., 24.7 ms ±   8.9 ms)
        local mean
        mean=$(echo "$mean_line" | awk '{print $5 " " $6}')
        echo "[$2] --> Hyperfine mean execution time: $mean" >> "$AVERAGE_LOG"
    else
        echo "[$2] --> Hyperfine mean execution time: N/A" >> "$AVERAGE_LOG"
    fi
}

parse_hyperfine_mean hyperfine_child-process.log "hyperfine_child-process"
parse_hyperfine_mean normal-file.log "hyperfine_normal-file"
parse_hyperfine_mean communication.log "hyperfine_communication"