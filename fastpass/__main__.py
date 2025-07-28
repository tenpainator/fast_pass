#!/usr/bin/env python3
"""
FastPass - Universal File Encryption/Decryption Tool

Makes package executable with 'python -m fastpass'
Entry point: MAIN PROGRAM ENTRY POINT
"""

# A1a: Load System Tools
import sys
import os
from pathlib import Path

# Add both fastpass directory and parent directory to path for imports
fastpass_path = Path(__file__).parent
parent_path = fastpass_path.parent
if str(parent_path) not in sys.path:
    sys.path.insert(0, str(parent_path))
if str(fastpass_path) not in sys.path:
    sys.path.insert(0, str(fastpass_path))

def main():
    """FastPass main entry point with complete error handling"""
    from cli import main as cli_main
    return cli_main()

if __name__ == "__main__":
    # Program Startup - FastPass application begins execution
    sys.exit(main())