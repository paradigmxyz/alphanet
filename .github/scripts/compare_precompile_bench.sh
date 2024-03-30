#!/usr/bin/env bash

main() {
    CRITERION_OUTPUT=${1:-criterion_output.txt}

    BENCHMARK_RESULTS="benchmark_results.tmp"

    > "$BENCHMARK_RESULTS"

    current_bench=""
    regressed=""

    while IFS= read -r line; do
        # Check for benchmark start
        if [[ $line =~ ^[a-zA-Z0-9_]+[[:space:]]+time: ]]; then
            current_bench=$(echo "$line" | awk '{print $1}')
        fi

        # Check for regression line
        if [[ $line =~ Performance\ has\ regressed\. ]]; then
            regressed="yes"
        fi

        # Check for change line and process it
        if [[ $line =~ change:\ \[ && $regressed == "yes" ]]; then
            # Extract the confidence interval percentage change
            avg_change=$(echo "$line" | awk -F'[][]' '{print $2}' | awk '{print $2}' | tr -d '%')

            # Check if change is greater than 5
            if (( $(echo "$avg_change > 5" | bc -l) )); then
                echo "$current_bench regressed by more than 5% ($avg_change%)" >> "$BENCHMARK_RESULTS"
            fi

            # Reset for the next benchmark
            regressed=""
        fi
    done < "$CRITERION_OUTPUT"

    # Check if any benchmarks regressed by more than 5%
    if [ -s "$BENCHMARK_RESULTS" ]; then
        echo "Some benchmarks have regressed by more than 5%:"
        cat "$BENCHMARK_RESULTS"
        rm "$BENCHMARK_RESULTS"
        exit 1
    else
        echo "No significant regressions detected."
        rm "$BENCHMARK_RESULTS"
    fi
}

main "${@}"
