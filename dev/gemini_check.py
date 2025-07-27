#!/usr/bin/env python3
"""
FastPass Project Status Checker - Uses existing repomix file
"""

import subprocess
from pathlib import Path

def main():
    print("FastPass Project Status Checker")
    print("Using existing temp_repomix.xml file")
    print("=" * 50)
    
    project_root = Path(__file__).parent.parent
    repomix_file = project_root / "temp_repomix.xml"
    
    if not repomix_file.exists():
        print(f"ERROR: Repomix file not found: {repomix_file}")
        print("Please run: cd c:\\Dev\\fast_pass && repomix --output temp_repomix.xml .")
        return
    
    print(f"Using repomix file: {repomix_file}")
    print("\nSending to Gemini for analysis...")
    
    # Simple prompt for Gemini
    prompt = ("Act as a critical technical reviewer. Analyze this FastPass codebase. "
             "Check if specification in dev/fast_pass_specification.md is fully implemented. "
             "Report: 1) What's missing 2) What's incomplete 3) Critical issues 4) Recommendations")
    
    # Build command string
    cmd = f'echo . | gemini -p "{prompt}" --all-files'
    
    try:
        # Execute in project directory
        result = subprocess.run(cmd, shell=True, cwd=str(project_root), 
                              capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("\n" + "=" * 80)
            print("GEMINI ANALYSIS")
            print("=" * 80)
            print(result.stdout)
            print("=" * 80)
        else:
            print(f"Gemini stderr: {result.stderr}")
            print(f"Gemini stdout: {result.stdout}")
            
    except subprocess.TimeoutExpired:
        print("ERROR: Gemini analysis timed out")
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("\nStatus check completed!")

if __name__ == "__main__":
    main()