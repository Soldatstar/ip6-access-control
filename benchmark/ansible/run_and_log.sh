#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error
set -u
# Pipelines fail if any command fails, not just the last one
set -o pipefail

# --- Configuration ---
RUNS=5000
# Define all benchmark targets with their demo names in an array of arrays
declare -A BENCHMARKS
BENCHMARKS["run"]="communication-demo"
BENCHMARKS["run2"]="files-demo"
BENCHMARKS["run3"]="child-demo"

# Create results directory
RESULTS_DIR="benchmark/results"
mkdir -p "$RESULTS_DIR"
AVERAGE_LOG="${RESULTS_DIR}/average_times.log"

# --- Helper Function to Run a Full Benchmark Suite ---
run_benchmark() {
    local make_target=$1
    local demo_name=$2
    local times_log="${RESULTS_DIR}/${make_target}_times.log"
    local supervisor_log="${RESULTS_DIR}/${make_target}_supervisor.log"

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

        local avg_line="[${make_target}:${demo_name}] --> Average execution time over ${total_runs_logged} runs: ${avg_time} ms."
        echo
        echo "Benchmark for 'make ${make_target}' (${demo_name}) complete."
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
for target in "${!BENCHMARKS[@]}"; do
    demo_name="${BENCHMARKS[$target]}"
    run_benchmark "$target" "$demo_name"
done

echo "===================================================="
echo "All benchmarks have been completed."
echo "===================================================="

# --- Additional Hyperfine and Binary Benchmarks ---
echo "Running extra benchmarks with hyperfine and direct execution..."

# 1. hyperfine for ./demo/child-process
hyperfine ./demo/child-process -N --warmup 5 --runs $RUNS \
  --export-json "${RESULTS_DIR}/hyperfine_child-process.json" \
  > "${RESULTS_DIR}/hyperfine_child-process.log"

# 2. hyperfine for ./demo/normal-file
hyperfine ./demo/normal-file -N --warmup 5 --runs $RUNS \
  --export-json "${RESULTS_DIR}/hyperfine_normal-file.json" \
  > "${RESULTS_DIR}/normal-file.log"

# 3. hyperfine for ./demo/communication
hyperfine ./demo/communication -N --warmup 5 --runs $RUNS \
  --export-json "${RESULTS_DIR}/hyperfine_communication.json" \
  > "${RESULTS_DIR}/communication.log"

echo "Extra benchmarks complete. Results saved to:"
echo "  ${RESULTS_DIR}/hyperfine_child-process.log (JSON: ${RESULTS_DIR}/hyperfine_child-process.json)"
echo "  ${RESULTS_DIR}/normal-file.log (JSON: ${RESULTS_DIR}/hyperfine_normal-file.json)"
echo "  ${RESULTS_DIR}/communication.log (JSON: ${RESULTS_DIR}/hyperfine_communication.json)"

# --- Append hyperfine results to summary file ---
parse_hyperfine_mean() {
    # $1: log file, $2: label, $3: demo name
    local mean_line
    mean_line=$(grep -m1 'Time (mean' "$1")
    if [[ -n "$mean_line" ]]; then
        # Extract the mean and stddev (e.g., 24.7 ms ±   8.9 ms)
        local mean
        mean=$(echo "$mean_line" | awk '{print $5 " " $6}')
        echo "[$2:$3] --> Hyperfine mean execution time: $mean" >> "$AVERAGE_LOG"
    else
        echo "[$2:$3] --> Hyperfine mean execution time: N/A" >> "$AVERAGE_LOG"
    fi
}

parse_hyperfine_mean "${RESULTS_DIR}/hyperfine_child-process.log" "hyperfine_child-process" "child-process-demo"
parse_hyperfine_mean "${RESULTS_DIR}/normal-file.log" "hyperfine_normal-file" "normal-file-demo"
parse_hyperfine_mean "${RESULTS_DIR}/communication.log" "hyperfine_communication" "communication-demo"

# Output the contents of average_times.log at the end
echo "===================================================="
echo "Final benchmark results from ${AVERAGE_LOG}:"
echo "===================================================="
cat "$AVERAGE_LOG"
echo "===================================================="