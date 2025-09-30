import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

plt.style.use('seaborn-v0_8')

FILE_SIZES = {
    '1kb': 1024,
    '100kb': 102400,
    '1mb': 1048576,
    '100mb': 104857600,
    '500mb': 524288000,
    '1gb': 1073741824
}

def load_data(path):
    data = {}
    
    client_csv = path / "client" / "client_metrics.csv"
    if client_csv.exists():
        data['client'] = pd.read_csv(client_csv)
    
    server_csv = path / "server" / "server_metrics.csv"
    if server_csv.exists():
        data['server'] = pd.read_csv(server_csv)
        
    return data

def load_all_size_data(base_path, implementation_type):
    all_data = {}
    
    for size_name, size_bytes in FILE_SIZES.items():
        if implementation_type == 'classical': results_dir = base_path / f"results_{size_name}_classical"
        else: results_dir = base_path / f"results_{size_name}_hybrid"
        
        if results_dir.exists():
            data = load_data(results_dir)
            if data:
                all_data[size_name] = {
                    'data': data,
                    'size_bytes': size_bytes,
                    'size_name': size_name
                }
    
    return all_data

def get_metric_columns(df):
    exclude_cols = {
        'tls_version', 'run_index', 'host', 'port', 'ciphers_requested', 
        'ca_file', 'cert_file', 'key_file', 'payload_bytes', 'use_hybrid',
        'negotiated_tls_version', 'negotiated_cipher', 'success',
        'bytes_sent', 'bytes_received', 'cert_size_bytes', 'key_size_bytes',
        'tcp_connect_time_ms', 'file_size_bytes', 'payload_size', 'file_size' 
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
        'ping_rtt_ms': ('Ping RTT', 'Time (ms)'),
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
    colors = ["#35B4EA", "#E3321A"]
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
    filename = f"{scope}/{metric}_comparison.png"
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
        colors = ['#35B4EA', '#E3321A']
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

def save_overhead_data(scope, classical_agg, hybrid_agg, output_dir):
    common_metrics = set(classical_agg.keys()) & set(hybrid_agg.keys())
    
    valid_metrics = []
    for metric in common_metrics:
        if (classical_agg[metric]['mean'] != 0 and 
            hybrid_agg[metric]['mean'] != 0):
            valid_metrics.append(metric)
    
    if not valid_metrics:
        return
    
    table_data = []
    for metric in sorted(valid_metrics):
        classical = classical_agg[metric]
        hybrid = hybrid_agg[metric]
        
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
    df = pd.DataFrame(table_data)
    filename = f"{scope}_{list(FILE_SIZES)[-1]}_overhead.csv"
    filepath = output_dir / filename
    df.to_csv(filepath, index=False)

def create_scaling_plot(metric, scope, classical_data, hybrid_data, output_dir):
    classical_sizes = []
    classical_means = []
    classical_stds = []
    hybrid_sizes = []
    hybrid_means = []
    hybrid_stds = []
    
    # Process classical data
    for size_name, size_data in classical_data.items():
        if scope in size_data['data']:
            df = size_data['data'][scope]
            if metric in df.columns:
                values = df[metric].dropna()
                if len(values) > 0 and values.mean() != 0:
                    classical_sizes.append(size_data['size_bytes'])
                    classical_means.append(values.mean())
                    classical_stds.append(values.std())
    
    # Process hybrid data
    for size_name, size_data in hybrid_data.items():
        if scope in size_data['data']:
            df = size_data['data'][scope]
            if metric in df.columns:
                values = df[metric].dropna()
                if len(values) > 0 and values.mean() != 0:
                    hybrid_sizes.append(size_data['size_bytes'])
                    hybrid_means.append(values.mean())
                    hybrid_stds.append(values.std())
    
    if not classical_sizes and not hybrid_sizes:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Plot classical data
    if classical_sizes:
        classical_sizes, classical_means, classical_stds = zip(*sorted(zip(classical_sizes, classical_means, classical_stds)))
        ax.errorbar(classical_sizes, classical_means, yerr=classical_stds, 
                   marker='o', linestyle='-', linewidth=2, markersize=8,
                   color='#35B4EA', label='Classical TLS', capsize=5, capthick=2)
    
    # Plot hybrid data
    if hybrid_sizes:
        hybrid_sizes, hybrid_means, hybrid_stds = zip(*sorted(zip(hybrid_sizes, hybrid_means, hybrid_stds)))
        ax.errorbar(hybrid_sizes, hybrid_means, yerr=hybrid_stds, 
                   marker='s', linestyle='-', linewidth=2, markersize=8,
                   color='#E3321A', label='Hybrid TLS', capsize=5, capthick=2)
    
    title, ylabel = get_metric_labels(metric)
    ax.set_xlabel('File Size (bytes)', fontsize=12, fontweight='bold')
    ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
    ax.set_title(f'{scope.title()} - {title} vs File Size', fontsize=14, fontweight='bold', pad=20)
    ax.set_xscale('log')
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=11)
    
    ax.set_xticks(list(FILE_SIZES.values()))
    ax.set_xticklabels([f'{size//1024}KB' if size < 1024*1024 else f'{size//(1024*1024)}MB' 
                       for size in FILE_SIZES.values()])
    
    plt.tight_layout()
    
    filename = f"{scope}/{metric}_scaling.png"
    filepath = output_dir / filename
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()


def create_scaling_summary_plot(scope, classical_data, hybrid_data, output_dir):
    all_metrics = set()
    for size_data in classical_data.values():
        if scope in size_data['data']:
            df = size_data['data'][scope]
            metrics = get_metric_columns(df)
            all_metrics.update(metrics)
    
    for size_data in hybrid_data.values():
        if scope in size_data['data']:
            df = size_data['data'][scope]
            metrics = get_metric_columns(df)
            all_metrics.update(metrics)
    
    valid_metrics = []
    for metric in all_metrics:
        has_data = False
        for size_data in classical_data.values():
            if scope in size_data['data']:
                df = size_data['data'][scope]
                if metric in df.columns:
                    values = df[metric].dropna()
                    if len(values) > 0 and values.mean() != 0:
                        has_data = True
                        break
        if has_data:
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
        
        classical_sizes = []
        classical_means = []
        classical_stds = []
        hybrid_sizes = []
        hybrid_means = []
        hybrid_stds = []
        
        #  classical 
        for size_name, size_data in classical_data.items():
            if scope in size_data['data']:
                df = size_data['data'][scope]
                if metric in df.columns:
                    values = df[metric].dropna()
                    if len(values) > 0 and values.mean() != 0:
                        classical_sizes.append(size_data['size_bytes'])
                        classical_means.append(values.mean())
                        classical_stds.append(values.std())
        
        #  hybrid 
        for size_name, size_data in hybrid_data.items():
            if scope in size_data['data']:
                df = size_data['data'][scope]
                if metric in df.columns:
                    values = df[metric].dropna()
                    if len(values) > 0 and values.mean() != 0:
                        hybrid_sizes.append(size_data['size_bytes'])
                        hybrid_means.append(values.mean())
                        hybrid_stds.append(values.std())
        
        if classical_sizes:
            classical_sizes, classical_means, classical_stds = zip(*sorted(zip(classical_sizes, classical_means, classical_stds)))
            ax.errorbar(classical_sizes, classical_means, yerr=classical_stds, 
                       marker='o', linestyle='-', linewidth=2, markersize=6,
                       color='#35B4EA', label='Classical', capsize=3, capthick=1)
        
        if hybrid_sizes:
            hybrid_sizes, hybrid_means, hybrid_stds = zip(*sorted(zip(hybrid_sizes, hybrid_means, hybrid_stds)))
            ax.errorbar(hybrid_sizes, hybrid_means, yerr=hybrid_stds, 
                       marker='s', linestyle='-', linewidth=2, markersize=6,
                       color='#E3321A', label='Hybrid', capsize=3, capthick=1)
        
        title, ylabel = get_metric_labels(metric)
        ax.set_title(title, fontweight='bold', fontsize=11)
        ax.set_xlabel('File Size', fontsize=10)
        ax.set_ylabel(ylabel, fontsize=10)
        ax.set_xscale('log')
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=9)
        
        ax.set_xticks(list(FILE_SIZES.values()))
        ax.set_xticklabels([f'{size//1024}KB' if size < 1024*1024 else f'{size//(1024*1024)}MB' 
                           for size in FILE_SIZES.values()], fontsize=9)
    
    for i in range(len(valid_metrics), len(axes)):
        axes[i].set_visible(False)
    
    fig.suptitle(f'{scope.title()} Metrics Scaling with File Size - Classical vs Hybrid TLS', 
                fontsize=16, fontweight='bold', y=0.98)
    
    plt.tight_layout()
    
    filename = f"{scope}_scaling_summary.png"
    filepath = output_dir / filename
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()


def main():
    classical_path = Path("classical_alice_bob")
    hybrid_path = Path("hybrid_qu_alice_bob")
    output_dir = Path("plots")
    output_dir.mkdir(exist_ok=True)
    (output_dir / "server").mkdir(parents=True, exist_ok=True)
    (output_dir / "client").mkdir(parents=True, exist_ok=True)
    
    print("Loading data from all file sizes...")
    
    classical_all_data = load_all_size_data(classical_path, 'classical')
    hybrid_all_data = load_all_size_data(hybrid_path, 'hybrid')
    
    print(f"Found classical data for sizes: {list(classical_all_data.keys())}")
    print(f"Found hybrid data for sizes: {list(hybrid_all_data.keys())}")
    
    print("Generating scaling plots...")
    for scope in ['client', 'server']:
        print(f"Processing {scope} data...")
        
        all_metrics = set()
        for size_data in classical_all_data.values():
            if scope in size_data['data']:
                df = size_data['data'][scope]
                metrics = get_metric_columns(df)
                all_metrics.update(metrics)
        
        for size_data in hybrid_all_data.values():
            if scope in size_data['data']:
                df = size_data['data'][scope]
                metrics = get_metric_columns(df)
                all_metrics.update(metrics)
        
        valid_metrics = []
        for metric in all_metrics:
            has_data = False
            for size_data in classical_all_data.values():
                if scope in size_data['data']:
                    df = size_data['data'][scope]
                    if metric in df.columns:
                        values = df[metric].dropna()
                        if len(values) > 0 and values.mean() != 0:
                            has_data = True
                            break
            if has_data: valid_metrics.append(metric)
        print(f"Found {len(valid_metrics)} valid metrics for {scope}")
        
        for metric in sorted(valid_metrics): create_scaling_plot(metric, scope, classical_all_data, hybrid_all_data, output_dir)
        create_scaling_summary_plot(scope, classical_all_data, hybrid_all_data, output_dir)
    
    
    # overhead on largest
    print("Calculating overhead for largest payload...")
    classical_data = load_data(classical_path / "logs")
    hybrid_data = load_data(hybrid_path / "logs")

    for scope in ['client', 'server']:
        if scope not in classical_data or scope not in hybrid_data:
            continue

        classical_df = classical_data[scope]
        hybrid_df = hybrid_data[scope]
        
        classical_metrics = get_metric_columns(classical_df)
        hybrid_metrics = get_metric_columns(hybrid_df)
        
        classical_agg = aggregate_metrics(classical_df, classical_metrics)
        hybrid_agg = aggregate_metrics(hybrid_df, hybrid_metrics)
        
        # common_metrics = set(classical_metrics) & set(hybrid_metrics)
        # valid_metrics = []
        # for metric in common_metrics:
        #     if (metric in classical_agg and metric in hybrid_agg and
        #         classical_agg[metric]['mean'] != 0 and hybrid_agg[metric]['mean'] != 0):
        #         valid_metrics.append(metric)
        # for metric in sorted(valid_metrics): create_comparison_plot(metric, scope, classical_agg, hybrid_agg, output_dir)
        # create_summary_plot(scope, classical_agg, hybrid_agg, output_dir)

        save_overhead_data(scope, classical_agg, hybrid_agg, output_dir)
    
    print("All plots generated.")

if __name__ == "__main__":
    main()