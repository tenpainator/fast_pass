#!/usr/bin/env python3
"""
Main application entry point
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Main function"""
    print("Hello from your new Python project!")
    print(f"Project root: {Path(__file__).parent}")
    
    # Your application logic goes here
    pass

if __name__ == "__main__":
    main()
