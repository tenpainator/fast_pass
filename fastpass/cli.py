"""FastPass CLI argument parsing and validation."""

import argparse
import sys
import json
import getpass
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastpass.utils.config import FastPassConfig
from fastpass.utils.logger import setup_logger, sanitize_error_message
from fastpass.app import FastPassApplication


def get_help_epilog() -> str:
    """Generate comprehensive help epilog with format support table and examples"""
    return """
SUPPORTED FILE FORMATS:

+--------+-----+  +--------+-----+  +--------+-----+
| Format | EDC |  | Format | EDC |  | Format | EDC |
+--------+-----+  +--------+-----+  +--------+-----+
| .pdf   | EDC |  | .docm  | EDC |  | .doc   | -DC |
| .docx  | EDC |  | .xlsm  | EDC |  | .xls   | -DC |
| .xlsx  | EDC |  | .pptm  | EDC |  | .ppt   | -DC |
| .pptx  | EDC |  | .dotx  | EDC |  |        |     |
| .potx  | EDC |  | .xltx  | EDC |  |        |     |
+--------+-----+  +--------+-----+  +--------+-----+

Legend: E=Encryption, D=Decryption, C=Check

USAGE EXAMPLES:

  # Encrypt file with password
  fastpass encrypt -i contract.docx -p "mypassword"
  fastpass encrypt -i "file with spaces.pdf" -p "secret"
  
  # Decrypt file with multiple password attempts
  fastpass decrypt -i encrypted.pdf -p "password123" "backup_pwd" "old_pwd"
  
  # Check if file is password protected
  fastpass check -i document.pdf
  fastpass check -i "my document.docx"
  
  # Specify output directory
  fastpass encrypt -i document.docx -p "secret" -o ./encrypted/
  
  # Use passwords from stdin (JSON array) - note: unquoted stdin
  echo '["pwd1", "pwd2", "pwd3"]' | fastpass decrypt -i file.pdf -p stdin
  
  # Combine CLI passwords with stdin passwords
  echo '["pwd3", "pwd4"]' | fastpass decrypt -i file.pdf -p "pwd1" "pwd2" stdin
  
  # Use literal string "stdin" as password (quoted)
  fastpass decrypt -i file.pdf -p "stdin"

COMMON FLAGS:
  -i, --input FILE              Input file to process
  -p, --password PWD [PWD ...]   Passwords to try (space-delimited)
                                 Use stdin (unquoted) to read JSON array from stdin
                                 Use "stdin" (quoted) to try literal string "stdin"
  -o, --output-dir DIR          Output directory (default: in-place)
  --debug                       Enable detailed logging (logs to %TEMP%\\fastpass_debug.log)
"""


def parse_command_line_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        prog="fastpass",
        description="FastPass - Universal file encryption and decryption tool",
        epilog=get_help_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'FastPass {FastPassConfig.VERSION}'
    )
    
    # Create subparsers for operations
    subparsers = parser.add_subparsers(dest='operation', help='Operation to perform')
    subparsers.required = False
    
    # Add operation subcommands
    encrypt_parser = subparsers.add_parser('encrypt', help='Add password protection to files')
    setup_common_arguments(encrypt_parser)
    
    decrypt_parser = subparsers.add_parser('decrypt', help='Remove password protection from files')
    setup_common_arguments(decrypt_parser)
    
    check_parser = subparsers.add_parser('check', help='Check if files require passwords')
    setup_common_arguments(check_parser)
    
    return parser.parse_args()


def setup_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Add common arguments to parser."""
    
    parser.add_argument(
        '-i', '--input',
        type=Path,
        help='File to process (quotes for spaces in path)'
    )
    
    parser.add_argument(
        '-p', '--password',
        nargs='+',
        help='Passwords to try (space-delimited, quotes for spaces, stdin for JSON array)'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        type=Path,
        help='Output directory (default: in-place modification)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable detailed logging and debug output'
    )



def validate_arguments(args: argparse.Namespace) -> None:
    """Validate parsed command line arguments."""
    if not args.operation:
        raise ValueError("Must specify an operation (encrypt, decrypt, or check)")
    
    has_file = hasattr(args, 'input') and args.input
    if not has_file:
        raise ValueError("Must specify a file to process (-i)")
    
    # Password required for encrypt/decrypt operations
    has_passwords = hasattr(args, 'password') and args.password
    if not has_passwords and args.operation != 'check':
        raise ValueError("Must specify passwords (-p)")


def handle_stdin_passwords(args: argparse.Namespace) -> None:
    """Process passwords from stdin if 'stdin' is specified in password list."""
    if hasattr(args, 'password') and args.password and 'stdin' in args.password:
        try:
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                stdin_passwords = json.loads(stdin_data)
                if not isinstance(stdin_passwords, list):
                    raise ValueError("stdin must contain a JSON array of passwords")
                
                # Replace 'stdin' with actual passwords from JSON
                password_list = []
                for p in args.password:
                    if p == 'stdin':
                        password_list.extend(stdin_passwords)
                    else:
                        password_list.append(p)
                args.password = password_list
            else:
                args.password = [p for p in args.password if p != 'stdin']
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON array in stdin: {e}")
        except Exception as e:
            raise ValueError(f"Error reading passwords from stdin: {e}")

def handle_interactive_passwords(args: argparse.Namespace) -> None:
    """Handle interactive password prompting when no passwords provided."""
    has_cli_passwords = hasattr(args, 'password') and args.password
    if not has_cli_passwords:
        if hasattr(args, 'operation') and args.operation in ['encrypt', 'decrypt']:
            try:
                if args.operation == 'encrypt':
                    password = getpass.getpass("Enter password for encryption: ")
                    confirm_password = getpass.getpass("Confirm password: ")
                    
                    if password != confirm_password:
                        raise ValueError("Passwords do not match")
                    
                    if not password:
                        raise ValueError("Password cannot be empty for encryption")
                    args.password = [password]
                    
                elif args.operation == 'decrypt':
                    password = getpass.getpass("Enter password for decryption: ")
                    if password:
                        args.password = [password]
                        
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
                sys.exit(1)
            except Exception as e:
                raise ValueError(f"Interactive password input failed: {e}")


def main() -> int:
    """Main entry point for FastPass CLI."""
    try:
        try:
            args = parse_command_line_arguments()
        except SystemExit as e:
            if e.code == 2:
                if len(sys.argv) > 1 and sys.argv[1].startswith('-'):
                    print("Error: Must specify an operation (encrypt, decrypt, or check)", file=sys.stderr)
                    return 2
            # Re-raise for help/version
            raise
        
        
        # Setup logging
        logger = setup_logger(
            debug=getattr(args, 'debug', False)
        )
        
        # Log startup
        logger.info(f"FastPass v{FastPassConfig.VERSION} starting")
        logger.debug(f"Operation: {args.operation}")
        
        validate_arguments(args)
        handle_stdin_passwords(args)
        handle_interactive_passwords(args)
        
        # Load configuration
        config = FastPassConfig.load_configuration(args)
        logger.debug(f"Configuration loaded: {len(config)} settings")
        
        # Run application
        app = FastPassApplication(args, logger, config)
        return app.run()
        
    except ValueError as e:
        print(f"Error: {sanitize_error_message(str(e))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 1
    except Exception as e:
        from fastpass.exceptions import FileFormatError, FileProcessingError
        error_msg = sanitize_error_message(str(e))
        if isinstance(e, (FileFormatError, FileProcessingError)) or \
           "Unsupported file format" in error_msg or \
           "File not found" in error_msg or \
           "Path resolution failed" in error_msg:
            print(f"[ERROR] {error_msg}", file=sys.stderr)
            return 1
        else:
            print(f"[ERROR] Unexpected error: {error_msg}", file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main())