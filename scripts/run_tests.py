#!/usr/bin/env python3
"""
FastPass Test Runner
Executes comprehensive test suite with reporting
Maps to: test_runner.py from test design document
"""

import subprocess
import sys
import time
from pathlib import Path


def run_test_suite():
    """Run complete test suite with coverage reporting"""
    
    print("Starting FastPass Comprehensive Test Suite")
    print("=" * 60)
    
    start_time = time.time()
    
    # Test execution phases
    test_phases = [
        ("CLI Basic Tests", "tests/test_cli_basic.py"),
        ("Integration Tests", "tests/test_integration_basic.py"),
    ]
    
    total_results = {
        "passed": 0,
        "failed": 0,
        "skipped": 0
    }
    
    for phase_name, test_path in test_phases:
        print(f"\nRunning {phase_name}")
        print("-" * 40)
        
        cmd = [
            "uv", "run", "python", "-m", "pytest",
            test_path,
            "-v",
            "--tb=short", 
            "--cov=src",
            "--cov-report=term-missing"
        ]
        
        try:
            result = subprocess.run(cmd, cwd=Path(__file__).parent.parent)
            
            if result.returncode == 0:
                print(f"SUCCESS: {phase_name} PASSED")
                total_results["passed"] += 1
            else:
                print(f"FAILED: {phase_name} FAILED")
                total_results["failed"] += 1
                
        except Exception as e:
            print(f"ERROR: {phase_name} ERROR: {e}")
            total_results["failed"] += 1
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\nTest Suite Complete")
    print(f"Total Duration: {duration:.2f} seconds")
    print(f"Results: {total_results['passed']} passed, {total_results['failed']} failed, {total_results['skipped']} skipped")
    
    # Return exit code
    return 0 if total_results["failed"] == 0 else 1


def run_all_tests():
    """Run all tests with coverage"""
    print("Running All FastPass Tests")
    print("=" * 50)
    
    cmd = [
        "uv", "run", "python", "-m", "pytest",
        "tests/",
        "-v",
        "--cov=src",
        "--cov-report=term-missing",
        "--cov-report=html:reports/coverage/"
    ]
    
    try:
        # Ensure reports directory exists
        reports_dir = Path(__file__).parent.parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        
        result = subprocess.run(cmd, cwd=Path(__file__).parent.parent)
        
        if result.returncode == 0:
            print("\nSUCCESS: All tests passed!")
            print("Coverage report: reports/coverage/index.html")
        else:
            print("\nFAILED: Some tests failed!")
        
        return result.returncode
        
    except Exception as e:
        print(f"ERROR: Error running tests: {e}")
        return 1


def demo_functionality():
    """Demonstrate FastPass functionality"""
    print("FastPass Functionality Demo")
    print("=" * 40)
    
    base_dir = Path(__file__).parent.parent
    
    # Demo commands
    demos = [
        ("Show supported formats", ["--list-supported"]),
        ("Show version", ["--version"]),
        ("Show help", ["--help"]),
    ]
    
    for demo_name, args in demos:
        print(f"\n{demo_name}:")
        print("-" * len(demo_name))
        
        cmd = ["uv", "run", "python", "-m", "src"] + args
        
        try:
            result = subprocess.run(cmd, cwd=base_dir, capture_output=True, text=True)
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "demo":
            demo_functionality()
        elif sys.argv[1] == "all":
            sys.exit(run_all_tests())
        elif sys.argv[1] == "suite":
            sys.exit(run_test_suite())
        else:
            print("Usage: python run_tests.py [demo|all|suite]")
            sys.exit(1)
    else:
        # Default: run all tests
        sys.exit(run_all_tests())