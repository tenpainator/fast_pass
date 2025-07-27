#!/usr/bin/env python3
"""
FastPass Project Status Checker
Uses Repomix analysis and Gemini to verify completion against specification
"""

import subprocess
import os
from pathlib import Path
import sys

def main():
    """Main execution function"""
    print("FastPass Project Status Checker")
    print("=" * 50)
    
    # Get project root directory (parent of dev folder)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    spec_path = script_dir / "fast_pass_specification.md"
    repomix_path = project_root / "temp_repomix.xml"
    
    print(f"Project root: {project_root}")
    print(f"Specification: {spec_path}")
    print(f"Repomix file: {repomix_path}")
    
    # Verify files exist
    if not spec_path.exists():
        print(f"[ERROR] Specification file not found: {spec_path}")
        sys.exit(1)
    
    if not repomix_path.exists():
        print(f"[ERROR] Repomix file not found. Please run: repomix --output temp_repomix.xml .")
        sys.exit(1)
    
    # Read specification file
    print(f"\nReading specification file...")
    try:
        with open(spec_path, 'r', encoding='utf-8') as f:
            specification_content = f.read()
        print(f"[SUCCESS] Loaded specification ({len(specification_content)} characters)")
    except Exception as e:
        print(f"[ERROR] Failed to read specification: {e}")
        sys.exit(1)
    
    # Prepare Gemini prompt
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
    
    # Send to Gemini via pipe
    print(f"Sending analysis to Gemini...")
    
    try:
        # Write prompt to temporary file with UTF-8 encoding
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as prompt_file:
            prompt_file.write(gemini_prompt)
            prompt_file_path = prompt_file.name
        
        try:
            # Read repomix content
            with open(repomix_path, 'r', encoding='utf-8') as f:
                repomix_content = f.read()
            
            # Create process for gemini using instruction file with proper encoding
            gemini_cmd = 'gemini.cmd' if os.name == 'nt' else 'gemini'
            
            # Set environment to use UTF-8
            env = os.environ.copy()
            if os.name == 'nt':
                env['PYTHONIOENCODING'] = 'utf-8'
            
            gemini_process = subprocess.Popen(
                [gemini_cmd, '--instruction-file-path', prompt_file_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                encoding='utf-8',
                env=env
            )
            
            # Send repomix content to gemini and get result
            stdout, stderr = gemini_process.communicate(input=repomix_content)
        finally:
            # Clean up prompt file
            try:
                os.unlink(prompt_file_path)
            except:
                pass
        
        if gemini_process.returncode == 0:
            print("\n" + "=" * 80)
            print("GEMINI PROJECT STATUS ANALYSIS")
            print("=" * 80)
            print(stdout)
            print("=" * 80)
        else:
            print(f"[ERROR] Gemini analysis failed:")
            print(f"STDERR: {stderr}")
            print(f"STDOUT: {stdout}")
            sys.exit(1)
            
    except Exception as e:
        print(f"[ERROR] Failed to run Gemini analysis: {e}")
        sys.exit(1)
    
    print("\n[SUCCESS] Project status check completed!")

if __name__ == "__main__":
    main()