#!/usr/bin/env python3
"""
Simple FastPass Project Status Checker
"""

import os
import subprocess
from pathlib import Path

def main():
    print("FastPass Project Status Checker")
    print("=" * 50)
    
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    print(f"Working in: {project_root}")
    
    # Step 1: Generate fresh repomix
    print("\nGenerating repomix analysis...")
    try:
        result = subprocess.run('repomix --output temp_status.xml .', 
                              shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"ERROR: {result.stderr}")
            return
        print("SUCCESS: Repomix generated")
    except Exception as e:
        print(f"ERROR: {e}")
        return
    
    # Step 2: Send to Gemini
    print("\nSending to Gemini...")
    
    prompt = ("Claude here. Act as a critical technical reviewer. "
             "I have a FastPass project (universal file encryption/decryption tool). "
             "Compare the codebase against the specification in dev/fast_pass_specification.md "
             "and provide: 1) COMPLETION STATUS 2) MISSING FEATURES 3) CRITICAL ISSUES "
             "4) RECOMMENDATIONS. Be thorough and critical.")
    
    try:
        # Use cmd directly for piping
        cmd = f'type temp_status.xml | gemini -p "{prompt}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("\n" + "=" * 80)
            print("GEMINI ANALYSIS")
            print("=" * 80)
            print(result.stdout)
            print("=" * 80)
        else:
            print(f"ERROR: {result.stderr}")
            
    except Exception as e:
        print(f"ERROR: {e}")
    
    # Cleanup
    try:
        os.remove('temp_status.xml')
        print("\nCleaned up temporary files")
    except:
        pass
    
    print("\nStatus check completed!")

if __name__ == "__main__":
    main()