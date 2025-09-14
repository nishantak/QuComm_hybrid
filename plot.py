import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

plt.style.use('seaborn-v0_8')

def load_data(path):
    data = {}
    
    # Load client metrics
    client_csv = path / "logs" / "client" / "client_metrics.csv"
    if client_csv.exists():
        data['client'] = pd.read_csv(client_csv)
    
    # Load server metrics
    server_csv = path / "logs" / "server" / "server_metrics.csv"
    if server_csv.exists():
        data['server'] = pd.read_csv(server_csv)
        
    return data

def get_metric_columns(df):
    exclude_cols = {
        'tls_version', 'run_index', 'host', 'port', 'ciphers_requested', 
        'ca_file', 'cert_file', 'key_file', 'payload_bytes', 'use_hybrid',
        'negotiated_tls_version', 'negotiated_cipher', 'success',
        'bytes_sent', 'bytes_received', 'cert_size_bytes', 'key_size_bytes',
        'tcp_connect_time_ms'
    }
    
    metric_cols = []
    for col in df.columns:
        if col not in exclude_cols and df[col].dtype in ['float64', 'int64']:
            if col != 'per_recv_call_time_ms':
                metric_cols.append(col)
    
    return sorted(metric_cols)

def aggregate_metrics(df, metric_cols):
    aggregated = {}
    for metric in metric_cols:
        if metric in df.columns:
            values = df[metric].dropna()
            if len(values) > 0:
                aggregated[metric] = {
                    'mean': values.mean(),
                    'std': values.std(),
                    'count': len(values)
                }
    return aggregated

def get_metric_labels(metric):
    labels = {
        'handshake_time_ms': ('Handshake Time', 'Time (ms)'),
        'tcp_connect_time_ms': ('TCP Connect Time', 'Time (ms)'),
        'rtt_ms': ('Round-Trip Time', 'Time (ms)'),
        'encrypt_time_ms': ('Encryption Time', 'Time (ms)'),
        'decrypt_time_ms': ('Decryption Time', 'Time (ms)'),
        'end_to_end_transfer_time_ms': ('End-to-End Transfer Time', 'Time (ms)'),
        'transfer_duration_ms': ('Transfer Duration', 'Time (ms)'),
        'throughput_bytes_per_sec': ('Throughput', 'Throughput (bytes/sec)')
    }
    return labels.get(metric, (metric.replace('_', ' ').title(), 'Value'))

def create_comparison_plot(metric, scope, classical_agg, hybrid_agg, output_dir):
    if metric not in classical_agg or metric not in hybrid_agg: return
    
    classical_mean = classical_agg[metric]['mean']
    hybrid_mean = hybrid_agg[metric]['mean']
    
    if classical_mean == 0 or hybrid_mean == 0:
        return
    
    # Create plot
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x_pos = [0, 1]
    means = [classical_mean, hybrid_mean]
    stds = [classical_agg[metric]['std'], hybrid_agg[metric]['std']]
    colors = ['#2E86AB', '#A23B72']
    labels = ['Classical TLS', 'Hybrid TLS']
    
    bars = ax.bar(x_pos, means, yerr=stds, color=colors, alpha=0.8, capsize=5)
    
    title, ylabel = get_metric_labels(metric)
    ax.set_xlabel('Implementation', fontsize=12, fontweight='bold')
    ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
    ax.set_title(f'{scope.title()} - {title}', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels)
    ax.grid(True, alpha=0.3)
    
    for bar, mean, std in zip(bars, means, stds):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + std + height*0.01,
               f'{mean:.2f}±{std:.2f}', ha='center', va='bottom', 
               fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    
    # Save plot
    filename = f"{scope}_{metric}_comparison.png"
    filepath = output_dir / filename
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()

def create_summary_plot(scope, classical_agg, hybrid_agg, output_dir):
    common_metrics = set(classical_agg.keys()) & set(hybrid_agg.keys())
    valid_metrics = []
    for metric in common_metrics:
        if (classical_agg[metric]['mean'] != 0 and 
            hybrid_agg[metric]['mean'] != 0):
            valid_metrics.append(metric)
    
    if not valid_metrics:
        return
    
    n_metrics = len(valid_metrics)
    n_cols = 3
    n_rows = (n_metrics + n_cols - 1) // n_cols
    
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5*n_rows))
    if n_rows == 1:
        axes = [axes] if n_cols == 1 else axes
    else:
        axes = axes.flatten()
    
    for i, metric in enumerate(sorted(valid_metrics)):
        ax = axes[i]
        
        classical_mean = classical_agg[metric]['mean']
        classical_std = classical_agg[metric]['std']
        hybrid_mean = hybrid_agg[metric]['mean']
        hybrid_std = hybrid_agg[metric]['std']
        
        x_pos = [0, 1]
        means = [classical_mean, hybrid_mean]
        stds = [classical_std, hybrid_std]
        colors = ['#2E86AB', '#A23B72']
        labels = ['Classical', 'Hybrid']
        
        bars = ax.bar(x_pos, means, yerr=stds, color=colors, alpha=0.8, capsize=5)
        
        title, ylabel = get_metric_labels(metric)
        ax.set_title(title, fontweight='bold')
        ax.set_ylabel(ylabel)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(labels)
        ax.grid(True, alpha=0.3)
        
        for bar, mean, std in zip(bars, means, stds):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + std + height*0.01,
                   f'{mean:.2f}±{std:.2f}', ha='center', va='bottom', 
                   fontsize=8, fontweight='bold')
    
    for i in range(len(valid_metrics), len(axes)):
        axes[i].set_visible(False)
    
    fig.suptitle(f'{scope.title()} Metrics Comparison - Classical vs Hybrid TLS', 
                fontsize=16, fontweight='bold', y=0.98)
    
    plt.tight_layout()
    
    filename = f"{scope}_summary_comparison.png"
    filepath = output_dir / filename
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()

def save_overhead_table(scope, classical_agg, hybrid_agg, output_dir):
    common_metrics = set(classical_agg.keys()) & set(hybrid_agg.keys())
    
    valid_metrics = []
    for metric in common_metrics:
        if (classical_agg[metric]['mean'] != 0 and 
            hybrid_agg[metric]['mean'] != 0):
            valid_metrics.append(metric)
    
    if not valid_metrics:
        return
    
    # Create overhead table data
    table_data = []
    for metric in sorted(valid_metrics):
        classical = classical_agg[metric]
        hybrid = hybrid_agg[metric]
        
        # Calculate overhead
        overhead = ((hybrid['mean'] - classical['mean']) / classical['mean']) * 100
        
        title, _ = get_metric_labels(metric)
        table_data.append({
            'Metric': title,
            'Classical_Mean': classical['mean'],
            'Classical_Std': classical['std'],
            'Hybrid_Mean': hybrid['mean'],
            'Hybrid_Std': hybrid['std'],
            'Overhead_Percent': overhead,
            'Classical_Count': classical['count'],
            'Hybrid_Count': hybrid['count']
        })
    
    # Save to CSV
    df = pd.DataFrame(table_data)
    filename = f"{scope}_overhead_table.csv"
    filepath = output_dir / filename
    df.to_csv(filepath, index=False)

def main():
    classical_path = Path("classical_alice_bob")
    hybrid_path = Path("hybrid_qu_alice_bob")
    output_dir = Path("plots")
    output_dir.mkdir(exist_ok=True)
    
    classical_data = load_data(classical_path)
    hybrid_data = load_data(hybrid_path)
    
    for scope in ['client', 'server']:
        if scope not in classical_data or scope not in hybrid_data:
            continue
                
        classical_df = classical_data[scope]
        hybrid_df = hybrid_data[scope]
        
        classical_metrics = get_metric_columns(classical_df)
        hybrid_metrics = get_metric_columns(hybrid_df)
        
        classical_agg = aggregate_metrics(classical_df, classical_metrics)
        hybrid_agg = aggregate_metrics(hybrid_df, hybrid_metrics)
        
        common_metrics = set(classical_metrics) & set(hybrid_metrics)
        valid_metrics = []
        for metric in common_metrics:
            if (metric in classical_agg and metric in hybrid_agg and
                classical_agg[metric]['mean'] != 0 and hybrid_agg[metric]['mean'] != 0):
                valid_metrics.append(metric)
        
        for metric in sorted(valid_metrics):
            create_comparison_plot(metric, scope, classical_agg, hybrid_agg, output_dir)
        
        create_summary_plot(scope, classical_agg, hybrid_agg, output_dir)
        
        save_overhead_table(scope, classical_agg, hybrid_agg, output_dir)

if __name__ == "__main__":
    main()