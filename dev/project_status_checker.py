#!/usr/bin/env python3
"""
FastPass Project Status Checker
Uses Repomix to analyze the entire codebase and Gemini to verify completion against specification
"""

import subprocess
import tempfile
import os
from pathlib import Path
import sys

def run_command(cmd, description):
    """Run a command and return its output"""
    print(f"[RUNNING] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] {description} failed:")
            print(f"STDERR: {result.stderr}")
            print(f"STDOUT: {result.stdout}")
            return None
        print(f"[SUCCESS] {description} completed")
        return result.stdout
    except Exception as e:
        print(f"[ERROR] {description} failed with exception: {e}")
        return None

def main():
    """Main execution function"""
    print("FastPass Project Status Checker")
    print("=" * 50)
    
    # Get project root directory (parent of dev folder)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    spec_path = script_dir / "fast_pass_specification.md"
    
    print(f"Project root: {project_root}")
    print(f"Specification: {spec_path}")
    
    # Verify specification file exists
    if not spec_path.exists():
        print(f"[ERROR] Specification file not found: {spec_path}")
        sys.exit(1)
    
    # Change to project root directory
    os.chdir(project_root)
    
    # Step 1: Generate repomix analysis of entire codebase
    print("\nGenerating codebase analysis with Repomix...")
    
    # Create temporary file for repomix output
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as temp_file:
        temp_xml_path = temp_file.name
    
    try:
        # Run repomix on the entire project with explicit command
        repomix_cmd = f'repomix.cmd --output "{temp_xml_path}" .'
        repomix_result = run_command(repomix_cmd, "Running Repomix analysis")
        
        if repomix_result is None:
            print("[ERROR] Failed to generate repomix analysis")
            sys.exit(1)
        
        # Step 2: Read specification file
        print(f"\nReading specification file...")
        try:
            with open(spec_path, 'r', encoding='utf-8') as f:
                specification_content = f.read()
            print(f"[SUCCESS] Loaded specification ({len(specification_content)} characters)")
        except Exception as e:
            print(f"[ERROR] Failed to read specification: {e}")
            sys.exit(1)
        
        # Step 3: Prepare Gemini prompt
        print(f"\nPreparing Gemini analysis...")
        
        gemini_prompt = f'''Claude here. I need you to act as a critical, neutral technical reviewer - do not agree by default or be sycophantic. Provide honest, analytical feedback as a critic rather than trying to be agreeable.

I have a FastPass project (universal file encryption/decryption tool) and need you to verify if the implementation matches the specification completely and correctly.

TASK: Compare the actual codebase implementation against the specification and provide:

1. **COMPLETION STATUS**: Is everything from the specification implemented? (Yes/No + details)
2. **CORRECTNESS ANALYSIS**: Are the implementations correct according to spec?
3. **MISSING FEATURES**: List any specified features that are missing or incomplete
4. **IMPLEMENTATION GAPS**: Identify any deviations from the specification
5. **CRITICAL ISSUES**: Any serious problems or security concerns
6. **RECOMMENDATIONS**: Specific actionable items to achieve full compliance

**SPECIFICATION DOCUMENT:**
{specification_content}

**COMPLETE CODEBASE ANALYSIS:**
[The repomix XML will be piped to stdin]

Please provide a thorough, critical analysis focusing on compliance with the specification.'''
        
        # Step 4: Send to Gemini via pipe
        print(f"Sending analysis to Gemini...")
        
        # Construct gemini command with piped input (Windows compatible)
        if os.name == 'nt':
            gemini_cmd = f'type "{temp_xml_path}" | gemini -p "{gemini_prompt}"'
        else:
            gemini_cmd = f'cat "{temp_xml_path}" | gemini -p "{gemini_prompt}"'
        
        gemini_result = run_command(gemini_cmd, "Running Gemini analysis")
        
        if gemini_result:
            print("\n" + "=" * 80)
            print("GEMINI PROJECT STATUS ANALYSIS")
            print("=" * 80)
            print(gemini_result)
            print("=" * 80)
        else:
            print("[ERROR] Failed to get Gemini analysis")
            sys.exit(1)
            
    finally:
        # Cleanup temporary file
        try:
            os.unlink(temp_xml_path)
            print(f"[CLEANUP] Removed temporary file: {temp_xml_path}")
        except Exception as e:
            print(f"[WARNING] Could not clean up temp file {temp_xml_path}: {e}")
    
    print("\n[SUCCESS] Project status check completed!")

if __name__ == "__main__":
    main()