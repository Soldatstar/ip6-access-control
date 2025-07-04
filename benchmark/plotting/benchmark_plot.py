#!/usr/bin/env python3
"""
Benchmark plotting tool for visualization of benchmark results.

This script can parse and visualize benchmark data from:
1. JSON files produced by hyperfine (units in seconds)
2. Simple text files with timing data (units in milliseconds)
"""

import os
import json
import argparse
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import matplotlib.ticker as ticker
from typing import List, Dict, Any, Tuple, Optional
import glob
from pathlib import Path


class BoxPlotData:
    """Data structure for box plot comparison data."""
    def __init__(self, name, mean, median, stddev, min_val, max_val):
        self.name = name
        self.mean = mean
        self.median = median
        self.stddev = stddev
        self.min_val = min_val
        self.max_val = max_val


def load_json_data(filepath: str) -> Dict[str, Any]:
    """Load benchmark data from a JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data


def load_text_data(filepath: str) -> List[float]:
    """Load benchmark data from a text file with one value per line."""
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        # Parse lines, skipping empty ones and converting to float
        data = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    value = float(line)
                    data.append(value)
                except ValueError:
                    continue
        
        return data
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return []


def analyze_data(data: List[float]) -> Dict[str, float]:
    """Analyze benchmark data and return statistics."""
    if not data:
        return {
            'mean': 0.0,
            'median': 0.0,
            'stddev': 0.0,
            'min': 0.0,
            'max': 0.0,
            'count': 0
        }
    
    return {
        'mean': np.mean(data),
        'median': np.median(data),
        'stddev': np.std(data),
        'min': min(data),
        'max': max(data),
        'count': len(data)
    }


def plot_histogram(data: List[float], title: str, xlabel: str, output_path: Optional[str] = None):
    """Create a histogram of the benchmark data."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    ax.hist(data, bins=15, alpha=0.7, color='skyblue', edgecolor='black')
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel('Frequency')
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Add mean and median lines
    mean_value = np.mean(data)
    median_value = np.median(data)
    
    ax.axvline(mean_value, color='red', linestyle='dashed', linewidth=1, label=f'Mean: {mean_value:.4f}')
    ax.axvline(median_value, color='green', linestyle='dashed', linewidth=1, label=f'Median: {median_value:.4f}')
    
    ax.legend()
    
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()
    plt.close(fig)


def plot_boxplot(data_dict: Dict[str, List[float]], title: str, ylabel: str, output_path: Optional[str] = None):
    """Create a box plot comparing multiple datasets."""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    box_data = [data for data in data_dict.values()]
    labels = list(data_dict.keys())
    
    bp = ax.boxplot(box_data, patch_artist=True, labels=labels)
    
    # Customize boxplot
    for i, box in enumerate(bp['boxes']):
        box.set(facecolor=f'C{i % 10}', alpha=0.7)
    
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.grid(True, linestyle='--', alpha=0.7)
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()
    plt.close(fig)


def plot_line(data: List[float], title: str, xlabel: str, ylabel: str, output_path: Optional[str] = None):
    """Create a line plot of the benchmark data to visualize trends."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = range(1, len(data) + 1)
    ax.plot(x, data, marker='o', linestyle='-', color='blue', markersize=5)
    
    # Add a trend line
    z = np.polyfit(x, data, 1)
    p = np.poly1d(z)
    ax.plot(x, p(x), "r--", alpha=0.7, label=f'Trend: {z[0]:.6f}x + {z[1]:.6f}')
    
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.legend()
    
    # Add run statistics
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    stats_text = (
        f'Mean: {np.mean(data):.4f}\n'
        f'Median: {np.median(data):.4f}\n'
        f'Std Dev: {np.std(data):.4f}\n'
        f'Min: {min(data):.4f}\n'
        f'Max: {max(data):.4f}'
    )
    ax.text(0.05, 0.95, stats_text, transform=ax.transAxes, fontsize=10,
            verticalalignment='top', bbox=props)
    
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()
    plt.close(fig)


def create_comparison_barplot(data: List[BoxPlotData], title: str, output_path: Optional[str] = None):
    """Create a comparison bar plot with error bars for multiple benchmarks."""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    names = [d.name for d in data]
    means = [d.mean for d in data]
    medians = [d.median for d in data]
    errors = [d.stddev for d in data]
    
    x = np.arange(len(names))
    width = 0.35
    
    # Create bars
    mean_bars = ax.bar(x - width/2, means, width, label='Mean', color='skyblue', alpha=0.7)
    median_bars = ax.bar(x + width/2, medians, width, label='Median', color='lightgreen', alpha=0.7)
    
    # Add error bars for mean
    ax.errorbar(x - width/2, means, yerr=errors, fmt='none', ecolor='black', capsize=5)
    
    # Customize plot
    ax.set_title(title)
    ax.set_ylabel('Execution Time (ms)')
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=45, ha='right')
    ax.legend()
    ax.grid(True, linestyle='--', alpha=0.7, axis='y')
    
    # Add value labels on bars
    def add_labels(bars):
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.2f}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontsize=8)
    
    add_labels(mean_bars)
    add_labels(median_bars)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()
    plt.close(fig)


def process_json_file(file_path: str, output_dir: str = None):
    """Process a JSON benchmark file and create visualizations."""
    data = load_json_data(file_path)
    
    if 'results' not in data:
        print(f"Error: Invalid JSON format in {file_path}")
        return
    
    for idx, result in enumerate(data['results']):
        command = os.path.basename(result['command'])
        times = result['times']
        
        # Convert seconds to milliseconds for better readability
        times_ms = [t * 1000 for t in times]
        
        base_filename = f"{command}_benchmark"
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            base_path = os.path.join(output_dir, base_filename)
        else:
            base_path = None
        
        # Create histogram
        hist_title = f"Distribution of Execution Times for {command}"
        hist_path = f"{base_path}_histogram.png" if base_path else None
        plot_histogram(times_ms, hist_title, "Execution Time (ms)", hist_path)
        
        # Create line plot
        line_title = f"Execution Times per Run for {command}"
        line_path = f"{base_path}_line.png" if base_path else None
        plot_line(times_ms, line_title, "Run Number", "Execution Time (ms)", line_path)
        
        # Analysis summary
        mean_ms = result['mean'] * 1000
        stddev_ms = result['stddev'] * 1000
        median_ms = result['median'] * 1000
        min_ms = result['min'] * 1000
        max_ms = result['max'] * 1000
        
        print(f"\nAnalysis for {command}:")
        print(f"Mean execution time: {mean_ms:.2f} ms")
        print(f"Median execution time: {median_ms:.2f} ms")
        print(f"Standard deviation: {stddev_ms:.2f} ms")
        print(f"Min execution time: {min_ms:.2f} ms")
        print(f"Max execution time: {max_ms:.2f} ms")


def process_text_file(file_path: str, output_dir: str = None):
    """Process a text benchmark file and create visualizations."""
    data = load_text_data(file_path)
    
    if not data:
        print(f"Error: No valid data found in {file_path}")
        return
    
    base_name = os.path.basename(file_path).split('.')[0]
    base_filename = f"{base_name}_benchmark"
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        base_path = os.path.join(output_dir, base_filename)
    else:
        base_path = None
    
    # Create histogram
    hist_title = f"Distribution of Execution Times for {base_name}"
    hist_path = f"{base_path}_histogram.png" if base_path else None
    plot_histogram(data, hist_title, "Execution Time (ms)", hist_path)
    
    # Create line plot
    line_title = f"Execution Times per Run for {base_name}"
    line_path = f"{base_path}_line.png" if base_path else None
    plot_line(data, line_title, "Run Number", "Execution Time (ms)", line_path)
    
    # Analysis summary
    analysis = analyze_data(data)
    print(f"\nAnalysis for {base_name}:")
    print(f"Mean execution time: {analysis['mean']:.2f} ms")
    print(f"Median execution time: {analysis['median']:.2f} ms")
    print(f"Standard deviation: {analysis['stddev']:.2f} ms")
    print(f"Min execution time: {analysis['min']:.2f} ms")
    print(f"Max execution time: {analysis['max']:.2f} ms")


def compare_multiple_files(file_paths: List[str], output_dir: str = None):
    """Compare data from multiple files in box plots and bar charts."""
    data_dict = {}
    
    for file_path in file_paths:
        base_name = os.path.basename(file_path).split('.')[0]
        machine_name = "unknown"
        
        # Try to extract machine name from path
        path_parts = Path(file_path).parts
        for part in path_parts:
            if part.startswith("benchie-"):
                machine_name = part
                break
        
        display_name = f"{machine_name}:{base_name}"
        
        if file_path.endswith('.json'):
            data = load_json_data(file_path)
            if 'results' in data and data['results']:
                result = data['results'][0]  # Take first result
                times = [t * 1000 for t in result['times']]  # Convert to ms
                data_dict[display_name] = times
        else:
            data = load_text_data(file_path)
            if data:
                data_dict[display_name] = data
    
    if not data_dict:
        print("No valid data found for comparison")
        return
    
    # Create output directory if needed
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Create box plot comparison
    box_title = "Execution Time Comparison"
    box_path = os.path.join(output_dir, "benchmark_comparison_boxplot.png") if output_dir else None
    plot_boxplot(data_dict, box_title, "Execution Time (ms)", box_path)
    
    # Create bar plot comparison
    box_data = []
    for name, values in data_dict.items():
        analysis = analyze_data(values)
        box_data.append(BoxPlotData(
            name=name,
            mean=analysis['mean'],
            median=analysis['median'],
            stddev=analysis['stddev'],
            min_val=analysis['min'],
            max_val=analysis['max']
        ))
    
    bar_path = os.path.join(output_dir, "benchmark_comparison_barplot.png") if output_dir else None
    create_comparison_barplot(box_data, "Benchmark Comparison", bar_path)
    
    # Print comparison summary
    print("\nComparison Summary:")
    for name, values in data_dict.items():
        analysis = analyze_data(values)
        print(f"{name}: Mean={analysis['mean']:.2f}ms, Median={analysis['median']:.2f}ms, StdDev={analysis['stddev']:.2f}ms")


def main():
    parser = argparse.ArgumentParser(description='Create visualizations for benchmark data')
    parser.add_argument('files', nargs='+', help='JSON or text files containing benchmark data')
    parser.add_argument('-o', '--output-dir', help='Directory to save output visualizations')
    parser.add_argument('-c', '--compare', action='store_true', help='Compare all input files')
    
    args = parser.parse_args()
    
    if args.compare and len(args.files) > 1:
        compare_multiple_files(args.files, args.output_dir)
    else:
        for file_path in args.files:
            if file_path.endswith('.json'):
                process_json_file(file_path, args.output_dir)
            else:
                process_text_file(file_path, args.output_dir)


if __name__ == "__main__":
    main()
