#!/usr/bin/env python3
"""
Main application entry point
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Main function - FastPass application entry point"""
    # A1a: Load System Tools - Import main application
    try:
        # Import and run the FastPass application
        from src.__main__ import main as fastpass_main
        return fastpass_main()
    except ImportError as e:
        print(f"Error: Could not import FastPass application: {e}")
        print(f"Please ensure you're running from the project root: {Path(__file__).parent}")
        return 1
    except Exception as e:
        print(f"Error: FastPass application failed: {e}")
        return 1

if __name__ == "__main__":
    main()
