import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# File sizes to test (in bytes)
FILE_SIZES = {
    "1KB": 1024,
    "100KB": 102400, 
    "1MB": 1048576,
    "100MB": 104857600,
    "500MB": 524288000,
    "1GB": 1073741824
}

NUM_RUNS = 16
def run_benchmark(implementation_dir, file_size_name, file_size_bytes, use_hybrid=False):
    print(f"\n{'='*60}")
    print(f"Running {implementation_dir} - {file_size_name} ({file_size_bytes:,} bytes)")
    print(f"Hybrid mode: {use_hybrid}")
    print(f"Number of runs: {NUM_RUNS}")
    print(f"{'='*60}")
    
    original_dir = os.getcwd()
    os.chdir(implementation_dir)
    try:
        cmd = [
            sys.executable, "benchmark.py",
            "--bytes", str(file_size_bytes),
            "--runs", str(NUM_RUNS)
        ]
        
        if use_hybrid:
            cmd.append("--hybrid")
        
        print(f"Test: {' '.join(cmd)}")
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        end_time = time.time()
        
        if result.returncode != 0:
            print(f"ERROR: Benchmark failed: {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False
        
        print(f"Benchmark completed in {end_time - start_time:.2f} seconds")
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"ERROR: Benchmark timed out after 300 seconds")
        return False
    except Exception as e:
        print(f"ERROR: Exception during benchmark: {e}")
        return False
    finally:
        os.chdir(original_dir)

def backup_and_organize_results(implementation_dir, file_size_name, file_size_bytes, use_hybrid=False):
    impl_path = Path(implementation_dir)
    logs_path = impl_path/"logs"
    
    if not logs_path.exists():
        print(f"No logs directory found in {implementation_dir}")
        return
    
    hybrid_suffix = "_hybrid" if use_hybrid else "_classical"
    backup_dir_name = f"results_{file_size_name.lower()}{hybrid_suffix}"
    backup_path = impl_path / backup_dir_name
    
    if backup_path.exists():
        shutil.rmtree(backup_path)
    
    shutil.copytree(logs_path, backup_path)
    print(f"Results backed up to: {backup_path}")

def main():
    print("Starting Comprehensive TLS Benchmark Suite")
    print(f"File sizes: {list(FILE_SIZES.keys())}")
    print(f"Runs per test: {NUM_RUNS}")
    print(f"Total tests: {len(FILE_SIZES) * 2} (classical + hybrid)")
    
    results_summary = {}
    
    # classical 

    print("\n" + "="*80)
    print("RUNNING CLASSICAL TLS BENCHMARKS")
    print("="*80)
    
    for file_size_name, file_size_bytes in FILE_SIZES.items():
        success = run_benchmark("classical_alice_bob", file_size_name, file_size_bytes, use_hybrid=False)
        if success:
            backup_and_organize_results("classical_alice_bob", file_size_name, file_size_bytes, use_hybrid=False)
            results_summary[f"classical_{file_size_name}"] = "SUCCESS"
        else:
            results_summary[f"classical_{file_size_name}"] = "FAILED"
        
        time.sleep(2)
    
    # Hybrid

    print("\n" + "="*80)
    print("RUNNING HYBRID TLS BENCHMARKS")
    print("="*80)
    
    for file_size_name, file_size_bytes in FILE_SIZES.items():
        success = run_benchmark("hybrid_qu_alice_bob", file_size_name, file_size_bytes, use_hybrid=True)
        if success:
            backup_and_organize_results("hybrid_qu_alice_bob", file_size_name, file_size_bytes, use_hybrid=True)
            results_summary[f"hybrid_{file_size_name}"] = "SUCCESS"
        else:
            results_summary[f"hybrid_{file_size_name}"] = "FAILED"
        
        time.sleep(2)
    
    print("\n" + "="*80)
    print("BENCHMARK SUMMARY")
    print("="*80)
    
    for test_name, status in results_summary.items():
        print(f"{test_name:25} : {status}")
    
    successful_tests = sum(1 for status in results_summary.values() if status == "SUCCESS")
    total_tests = len(results_summary)
    
    print(f"\nSuccessful tests: {successful_tests}/{total_tests}")
    
    if successful_tests == total_tests: print("All")
    else: print("Fail")

if __name__ == "__main__":
    main()
