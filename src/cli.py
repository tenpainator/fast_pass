"""
FastPass CLI Argument Parsing and Validation
Maps to: Section A - DETAILED CLI PARSING from flowchart
"""

# A1a: Load System Tools
import argparse
import sys
import json
from pathlib import Path
from typing import List, Optional, Dict, Any

from utils.config import FastPassConfig
from utils.logger import setup_logger, sanitize_error_message


def parse_command_line_arguments() -> argparse.Namespace:
    """
    A1b: Initialize Command Reader
    Create a system to understand user commands
    Set up FastPass name and help description
    """
    parser = argparse.ArgumentParser(
        prog="fast_pass",
        description="FastPass - Universal file encryption and decryption tool",
        epilog="""
Examples:
  fast_pass encrypt -i contract.docx -p "mypassword"
  fast_pass decrypt -i file1.pdf file2.docx -p "shared_pwd"
  fast_pass decrypt -r ./encrypted_docs/ -p "main_password"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # A1g: Add Helper Features with Enhanced Logging  
    parser.add_argument(
        '--list-supported',
        action='store_true',
        help='List supported file formats'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'FastPass {FastPassConfig.VERSION}'
    )
    
    # A1c: Define Main Operation Choice
    # User must choose either encrypt OR decrypt
    # Cannot do both operations simultaneously
    subparsers = parser.add_subparsers(dest='operation', help='Operation to perform')
    subparsers.required = False  # Allow for info commands
    
    # Encrypt operation
    encrypt_parser = subparsers.add_parser('encrypt', help='Add password protection to files')
    setup_common_arguments(encrypt_parser)
    
    # Decrypt operation  
    decrypt_parser = subparsers.add_parser('decrypt', help='Remove password protection from files')
    setup_common_arguments(decrypt_parser)
    
    # Add recursive option to decrypt and check-password only
    decrypt_parser.add_argument(
        '-r', '--recursive',
        type=Path,
        help='Process directory recursively (decrypt/check-password only)'
    )
    
    # Check password operation
    check_parser = subparsers.add_parser('check-password', help='Check if files require passwords')
    setup_common_arguments(check_parser)
    check_parser.add_argument(
        '-r', '--recursive',
        type=Path,
        help='Process directory recursively'
    )
    
    # Note: encrypt parser deliberately does not have -r option for security
    
    
    return parser.parse_args()


def setup_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Setup arguments common to all operations"""
    
    # A1d: Set Up File Input Options
    # Use -i/--input flag for space-delimited files
    # Require explicit file specification with quotes for spaced paths
    parser.add_argument(
        '-i', '--input',
        nargs='+',
        type=Path,
        help='Files to process (space-delimited, quotes for spaces)'
    )
    
    # A1e: Configure Password Options with Space Delimitation
    # Accept space-delimited passwords with -p flag
    # Support password file and JSON stdin options
    parser.add_argument(
        '-p', '--password',
        nargs='+',
        help='Passwords to try (space-delimited, quotes for spaces, or "stdin" for JSON)'
    )
    
    parser.add_argument(
        '--password-list',
        type=Path,
        help='Text file with passwords to try (one per line)'
    )
    
    # A1f: Set Output Location Options
    # Choose where processed files should be saved
    # Default: replace original files in same location
    parser.add_argument(
        '-o', '--output-dir',
        type=Path,
        help='Output directory (default: in-place modification)'
    )
    
    # A1g: Add Helper Features
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Deep verification of processed files'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable detailed logging and debug output'
    )
    
    parser.add_argument(
        '--log-file',
        type=Path,
        help='Log file path for detailed logging'
    )


def display_information_and_exit(args: argparse.Namespace) -> int:
    """
    A1i: Handle Information Requests
    Check if user wants to see supported file formats
    Show list and exit if that's all they wanted
    """
    if getattr(args, 'list_supported', False):
        # A1i_List: Show Supported File Types
        print("FastPass Supported File Formats:")
        print("\nModern Office Documents (experimental encryption, full decryption):")
        office_formats = [ext for ext, tool in FastPassConfig.SUPPORTED_FORMATS.items() 
                         if tool == 'msoffcrypto']
        for fmt in sorted(office_formats):
            print(f"  {fmt}")
        
        print("\nPDF Documents (full encryption and decryption support):")
        pdf_formats = [ext for ext, tool in FastPassConfig.SUPPORTED_FORMATS.items() 
                      if tool == 'PyPDF2']
        for fmt in sorted(pdf_formats):
            print(f"  {fmt}")
        
        print("\nLegacy Office Formats (NOT SUPPORTED):")
        print("  .doc, .xls, .ppt (use Office to convert to modern format)")
        
        return 0
    
    return 0


def validate_arguments(args: argparse.Namespace) -> None:
    """
    A2a: Check Input Requirements
    User must specify either files or folder to process
    Cannot proceed without something to work on
    """
    
    # Skip validation for info commands
    if getattr(args, 'list_supported', False):
        return
    
    # Must have an operation for non-info commands
    if not args.operation:
        raise ValueError("Must specify an operation (encrypt, decrypt, or check-password)")
    
    # A2a_Check: Valid Input Method Provided?
    has_files = hasattr(args, 'input') and args.input
    has_recursive = hasattr(args, 'recursive') and args.recursive
    
    if not has_files and not has_recursive:
        # A2a_Error: Nothing to Process
        raise ValueError("Must specify either files (-i) or recursive directory (-r)")
    
    if has_files and has_recursive:
        # A2a_Both_Error: Conflicting Instructions
        raise ValueError("Cannot specify both individual files and recursive directory")
    
    # A2a1: Validate Recursive Mode Usage
    # Check if recursive mode used with encrypt operation
    # Recursive mode only allowed with decrypt/check-password
    if has_recursive and args.operation == 'encrypt':
        # A2a1_Error: Recursive Encryption Blocked
        raise ValueError("Recursive mode only supported for decrypt operations (security restriction)")
    
    # Validate password requirements
    has_passwords = (hasattr(args, 'password') and args.password) or \
                   (hasattr(args, 'password_list') and args.password_list)
    
    if not has_passwords and args.operation != 'check-password':
        raise ValueError("Must specify passwords (-p) or password list (--password-list)")


def handle_stdin_passwords(args: argparse.Namespace) -> None:
    """
    A3d: Handle Stdin Password Input
    Check for 'stdin' in CLI passwords
    Parse JSON password mapping from stdin if specified
    """
    if hasattr(args, 'password') and args.password and 'stdin' in args.password:
        try:
            # Read JSON from stdin
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                password_mapping = json.loads(stdin_data)
                # Store the mapping for later use
                args.stdin_password_mapping = password_mapping
                # Remove 'stdin' from password list
                args.password = [p for p in args.password if p != 'stdin']
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in stdin: {e}")
        except Exception as e:
            raise ValueError(f"Error reading passwords from stdin: {e}")


def main() -> int:
    """
    Main Control Center
    Sets up error handling for entire program
    Prepares to read user's command-line instructions
    """
    try:
        # A1h: Read User's Commands
        # Process the command-line instructions user provided
        # Handle cases where user asks for help or makes errors
        args = parse_command_line_arguments()
        
        # A1i: Handle Information Requests
        if hasattr(args, 'list_supported') and args.list_supported:
            return display_information_and_exit(args)
        
        # A3a-A3e: Enhanced Logging Setup
        logger = setup_logger(
            debug=getattr(args, 'debug', False),
            log_file=getattr(args, 'log_file', None)
        )
        
        # A3e: Record Program Startup with Config
        logger.info(f"FastPass v{FastPassConfig.VERSION} starting")
        logger.debug(f"Operation: {args.operation}")
        
        # Validate arguments
        validate_arguments(args)
        
        # Handle stdin passwords
        handle_stdin_passwords(args)
        
        # Load configuration
        config = FastPassConfig.load_configuration(args)
        logger.debug(f"Configuration loaded: {len(config)} settings")
        
        # Import and run main application
        from app import FastPassApplication
        app = FastPassApplication(args, logger, config)
        return app.run()
        
    except ValueError as e:
        # A1h_Error: Invalid User Input
        print(f"Error: {sanitize_error_message(str(e))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 1
    except Exception as e:
        # Unexpected error
        print(f"Unexpected error: {sanitize_error_message(str(e))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())