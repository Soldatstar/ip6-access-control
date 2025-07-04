#!/usr/bin/env python3
"""
Utility functions for benchmark plotting.
"""

import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from typing import List, Dict, Any, Tuple, Optional, NamedTuple
from dataclasses import dataclass


@dataclass
class BoxPlotData:
    """Data structure for box plot comparison data."""
    name: str
    mean: float
    median: float
    stddev: float
    min_val: float
    max_val: float


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


def create_violin_plot(data_dict: Dict[str, List[float]], title: str, ylabel: str, output_path: Optional[str] = None):
    """Create a violin plot for comparing distributions."""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    positions = range(1, len(data_dict) + 1)
    data_values = list(data_dict.values())
    
    violins = ax.violinplot(data_values, positions, vert=True, widths=0.7,
                          showmeans=True, showextrema=True, showmedians=True)
    
    # Customize violins
    for i, pc in enumerate(violins['bodies']):
        pc.set_facecolor(f'C{i % 10}')
        pc.set_alpha(0.7)
    
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(positions)
    ax.set_xticklabels(data_dict.keys(), rotation=45, ha='right')
    ax.grid(True, linestyle='--', alpha=0.7, axis='y')
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()
    plt.close(fig)


def plot_time_series(data_dict: Dict[str, List[float]], title: str, xlabel: str, ylabel: str, output_path: Optional[str] = None):
    """Create a time series plot comparing multiple datasets."""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    for name, values in data_dict.items():
        x = range(1, len(values) + 1)
        ax.plot(x, values, marker='o', linestyle='-', label=name, markersize=4, alpha=0.7)
    
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.legend()
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()
    plt.close(fig)
