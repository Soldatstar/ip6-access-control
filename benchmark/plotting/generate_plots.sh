#!/bin/bash

# Configuration
PLOT_SCRIPT="benchmark_plot.py"
RESULTS_DIR="../results"
OUTPUT_DIR="plots"
MACHINES=("benchie-1" "benchie-2")

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Process each machine's results
for machine in "${MACHINES[@]}"; do
    echo "Processing results for $machine..."
    machine_dir="${RESULTS_DIR}/${machine}"
    pwd
    # Skip if machine directory doesn't exist
    if [[ ! -d "$machine_dir" ]]; then
        echo "  No results found for $machine, skipping."
        continue
    fi
    
    # Create machine-specific output directory
    machine_output_dir="${OUTPUT_DIR}/${machine}"
    mkdir -p "$machine_output_dir"
    
    # Process JSON files (hyperfine results)
    json_files=("${machine_dir}"/*.json)
    if [[ -e "${json_files[0]}" ]]; then
        echo "  Processing JSON files..."
        python "$PLOT_SCRIPT" "${json_files[@]}" -o "$machine_output_dir"
    fi
    
    # Process log files (times)
    log_files=("${machine_dir}"/*.log)
    if [[ -e "${log_files[0]}" ]]; then
        echo "  Processing log files..."
        for log_file in "${log_files[@]}"; do
            if [[ "$log_file" == *"_times.log" ]]; then
                echo "    Processing $log_file"
                python "$PLOT_SCRIPT" "$log_file" -o "$machine_output_dir"
            fi
        done
    fi
done

# Create comparison plots across machines
echo "Creating machine comparison plots..."
mkdir -p "${OUTPUT_DIR}/comparisons"

# Compare similar files across machines
for file_type in "hyperfine_child-process.json" "hyperfine_normal-file.json" "hyperfine_communication.json" "run_times.log" "run2_times.log" "run3_times.log"; do
    comparison_files=()
    for machine in "${MACHINES[@]}"; do
        file_path="${RESULTS_DIR}/${machine}/${file_type}"
        if [[ -f "$file_path" ]]; then
            comparison_files+=("$file_path")
        fi
    done
    
    if [[ ${#comparison_files[@]} -gt 1 ]]; then
        echo "  Comparing ${file_type} across machines..."
        python "$PLOT_SCRIPT" "${comparison_files[@]}" -c -o "${OUTPUT_DIR}/comparisons"
    fi
done

echo "Plot generation complete. Results saved to $OUTPUT_DIR"
