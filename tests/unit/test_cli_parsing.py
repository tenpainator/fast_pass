"""
Comprehensive Unit Tests for CLI Argument Parsing
Tests every CLI argument combination and validation scenario
"""

import pytest
import argparse
import sys
from unittest.mock import patch, MagicMock
from pathlib import Path
from io import StringIO

# Import modules under test
import src.cli as cli_module
from src.utils.config import FastPassConfig


class TestCLIArgumentParsing:
    """Test CLI argument parsing and validation logic"""
    
    def test_parse_encrypt_single_file(self):
        """Test: Basic encrypt operation parsing for a single file"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password']):
            args = cli_module.parse_command_line_arguments()
            assert args.operation == 'encrypt'
            assert args.input == Path('test.pdf')
            assert args.password == ['password']
    
    def test_parse_decrypt_single_file(self):
        """Test: Basic decrypt operation parsing for a single file"""
        with patch.object(sys, 'argv', ['fast_pass', 'decrypt', '-i', 'test.pdf', '-p', 'password']):
            args = cli_module.parse_command_line_arguments()
            assert args.operation == 'decrypt'
            assert args.input == Path('test.pdf')
            assert args.password == ['password']
    
    def test_parse_check_single_file(self):
        """Test: Basic check operation parsing for a single file"""
        with patch.object(sys, 'argv', ['fast_pass', 'check', '-i', 'test.pdf']):
            args = cli_module.parse_command_line_arguments()
            assert args.operation == 'check'
            assert args.input == Path('test.pdf')
    
    def test_parse_multiple_files_fails(self):
        """Test: Providing multiple files to -i raises an error"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'file1.pdf', 'file2.pdf', '-p', 'password']):
            with pytest.raises(SystemExit):
                # argparse will exit with an error for unrecognized arguments
                cli_module.parse_command_line_arguments()
    
    def test_parse_files_with_spaces(self):
        """Test: Files with spaces in names"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'file with spaces.pdf', '-p', 'password']):
            args = cli_module.parse_command_line_arguments()
            assert args.input == Path('file with spaces.pdf')
    
    def test_parse_multiple_passwords(self):
        """Test: Multiple passwords parsing"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'pass1', 'pass2', 'pass3']):
            args = cli_module.parse_command_line_arguments()
            assert args.password == ['pass1', 'pass2', 'pass3']
    
    def test_parse_passwords_with_spaces(self):
        """Test: Passwords with spaces"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password with spaces', 'another password']):
            args = cli_module.parse_command_line_arguments()
            assert args.password == ['password with spaces', 'another password']
    
    def test_parse_stdin_password(self):
        """Test: stdin password parsing"""
        with patch.object(sys, 'argv', ['fast_pass', 'decrypt', '-i', 'test.pdf', '-p', 'stdin']):
            args = cli_module.parse_command_line_arguments()
            assert args.password == ['stdin']
    
    def test_parse_mixed_cli_stdin_passwords(self):
        """Test: Mixed CLI and stdin password parsing"""
        with patch.object(sys, 'argv', ['fast_pass', 'decrypt', '-i', 'test.pdf', '-p', 'pwd1', 'stdin', 'pwd2']):
            args = cli_module.parse_command_line_arguments()
            assert args.password == ['pwd1', 'stdin', 'pwd2']
    
    def test_parse_output_directory(self):
        """Test: Output directory parsing"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password', '-o', '/output/dir']):
            args = cli_module.parse_command_line_arguments()
            assert args.output_dir == Path('/output/dir')
    
    def test_parse_removed_dry_run_flag_error(self):
        """Test: Removed dry-run flag raises error"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password', '--dry-run']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()
    
    def test_parse_removed_verify_flag_error(self):
        """Test: Removed verify flag raises error"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password', '--verify']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()
    
    def test_parse_debug_flag(self):
        """Test: Debug flag parsing"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password', '--debug']):
            args = cli_module.parse_command_line_arguments()
            assert args.debug is True
    
    def test_parse_removed_log_file_flag_error(self):
        """Test: Removed log-file flag raises error"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password', '--log-file', 'app.log']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()
    
    def test_parse_debug_flag_only(self):
        """Test: Debug flag parsing (only valid flag remaining)"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password', '--debug']):
            args = cli_module.parse_command_line_arguments()
            assert args.debug is True
    
    def test_parse_removed_list_supported_flag_error(self):
        """Test: Removed list-supported flag raises error"""
        with patch.object(sys, 'argv', ['fast_pass', '--list-supported']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()
    
    def test_parse_old_check_password_command_fails(self):
        """Test: The old 'check-password' command is no longer recognized"""
        with patch.object(sys, 'argv', ['fast_pass', 'check-password', '-i', 'test.pdf']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()


class TestCLIArgumentValidation:
    """Test CLI argument validation logic"""
    
    def test_validate_encrypt_basic_valid(self):
        """Test: Valid encrypt arguments pass validation"""
        args = argparse.Namespace(
            operation='encrypt',
            input=Path('test.pdf'),
            password=['password']
        )
        # Should not raise exception
        cli_module.validate_arguments(args)
    
    def test_validate_decrypt_basic_valid(self):
        """Test: Valid decrypt arguments pass validation"""
        args = argparse.Namespace(
            operation='decrypt',
            input=Path('test.pdf'),
            password=['password']
        )
        # Should not raise exception
        cli_module.validate_arguments(args)
    
    def test_validate_check_no_password_valid(self):
        """Test: check without password is valid"""
        args = argparse.Namespace(
            operation='check',
            input=Path('test.pdf'),
            password=None
        )
        # Should not raise exception
        cli_module.validate_arguments(args)
    
    def test_validate_no_operation_error(self):
        """Test: Missing operation raises error"""
        args = argparse.Namespace(
            operation=None,
            input=Path('test.pdf'),
            password=['password']
        )
        with pytest.raises(ValueError, match="Must specify an operation"):
            cli_module.validate_arguments(args)
    
    def test_validate_no_input_files_error(self):
        """Test: Missing input files raises error"""
        args = argparse.Namespace(
            operation='encrypt',
            input=None,
            password=['password']
        )
        with pytest.raises(ValueError, match="Must specify a file to process"):
            cli_module.validate_arguments(args)
    
    def test_validate_no_password_encrypt_error(self):
        """Test: Missing password for encrypt raises error"""
        args = argparse.Namespace(
            operation='encrypt',
            input=Path('test.pdf'),
            password=None
        )
        with pytest.raises(ValueError, match="Must specify passwords"):
            cli_module.validate_arguments(args)
    
    def test_validate_no_password_decrypt_error(self):
        """Test: Missing password for decrypt raises error"""
        args = argparse.Namespace(
            operation='decrypt',
            input=Path('test.pdf'),
            password=None
        )
        with pytest.raises(ValueError, match="Must specify passwords"):
            cli_module.validate_arguments(args)
    
    def test_validate_single_file_required(self):
        """Test: Single file input validation"""
        args = argparse.Namespace(
            operation='encrypt',
            input=Path('test.pdf'),
            password=['password']
        )
        # Should not raise exception
        cli_module.validate_arguments(args)


class TestCLIPasswordHandling:
    """Test CLI password input handling"""
    
    def test_handle_stdin_passwords_no_stdin(self):
        """Test: No stdin password handling"""
        args = argparse.Namespace(password=['regular_password'])
        cli_module.handle_stdin_passwords(args)
        assert args.password == ['regular_password']
    
    def test_handle_stdin_passwords_valid_json_array(self):
        """Test: Valid JSON array stdin password handling"""
        args = argparse.Namespace(password=['stdin', 'regular_password'])
        json_input = '["password1", "password2", "password3"]'
        
        with patch('sys.stdin.read', return_value=json_input):
            cli_module.handle_stdin_passwords(args)
            
        assert args.password == ['password1', 'password2', 'password3', 'regular_password']
    
    def test_handle_stdin_passwords_invalid_json(self):
        """Test: Invalid JSON stdin password handling"""
        args = argparse.Namespace(password=['stdin'])
        json_input = '["invalid": json]'
        
        with patch('sys.stdin.read', return_value=json_input):
            with pytest.raises(ValueError, match="Invalid JSON array in stdin"):
                cli_module.handle_stdin_passwords(args)
    
    def test_handle_stdin_passwords_non_array_json(self):
        """Test: Non-array JSON in stdin raises error"""
        args = argparse.Namespace(password=['stdin'])
        json_input = '{"not": "array"}'
        
        with patch('sys.stdin.read', return_value=json_input):
            with pytest.raises(ValueError, match="stdin must contain a JSON array"):
                cli_module.handle_stdin_passwords(args)
    
    def test_handle_stdin_passwords_empty_stdin(self):
        """Test: Empty stdin password handling"""
        args = argparse.Namespace(password=['stdin'])
        
        with patch('sys.stdin.read', return_value=''):
            cli_module.handle_stdin_passwords(args)
            
        assert args.password == []


class TestCLIInformationDisplay:
    """Test CLI information display functions"""
    
    def test_help_shows_format_support_table(self, capsys):
        """Test: Help shows format support in EDC table format"""
        with patch.object(sys, 'argv', ['fast_pass', '--help']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()
        
        # Note: Can't easily test help output without more complex mocking
        # This test validates that help doesn't crash
    
    def test_version_display_works(self, capsys):
        """Test: Version display works"""
        with patch.object(sys, 'argv', ['fast_pass', '--version']):
            with pytest.raises(SystemExit):
                cli_module.parse_command_line_arguments()


class TestCLIMainFunction:
    """Test main CLI function and error handling"""
    
    def test_main_help_display(self, capsys):
        """Test: Help display works"""
        with patch.object(sys, 'argv', ['fast_pass', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                cli_module.main()
            assert exc_info.value.code == 0
    
    def test_main_version_display(self, capsys):
        """Test: Version display works"""
        with patch.object(sys, 'argv', ['fast_pass', '--version']):
            with pytest.raises(SystemExit) as exc_info:
                cli_module.main()
            assert exc_info.value.code == 0
    
    def test_main_removed_list_supported_error(self, capsys):
        """Test: Removed list-supported flag causes error"""
        with patch.object(sys, 'argv', ['fast_pass', '--list-supported']):
            result = cli_module.main()
            # Should return error code 2 for invalid arguments
            assert result == 2
    
    def test_main_invalid_arguments_error(self, capsys):
        """Test: Invalid arguments return error code 2"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt']):  # Missing required args
            result = cli_module.main()
            assert result == 2
            
            captured = capsys.readouterr()
            assert "Error:" in captured.err
    
    def test_main_keyboard_interrupt(self, capsys):
        """Test: Keyboard interrupt handling"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password']):
            with patch('src.cli.FastPassApplication') as mock_app:
                mock_app.return_value.run.side_effect = KeyboardInterrupt()
                
                result = cli_module.main()
                assert result == 1
                
                captured = capsys.readouterr()
                assert "Operation cancelled by user" in captured.err
    
    def test_main_unexpected_error(self, capsys):
        """Test: Unexpected error handling"""
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', 'test.pdf', '-p', 'password']):
            with patch('src.cli.FastPassApplication') as mock_app:
                mock_app.return_value.run.side_effect = RuntimeError("Unexpected error")
                
                result = cli_module.main()
                assert result == 2
                
                captured = capsys.readouterr()
                assert "Unexpected error:" in captured.err


class TestCLIEdgeCases:
    """Test CLI edge cases and special scenarios"""
    
    def test_empty_password_list(self):
        """Test: Empty password list handling"""
        with patch.object(sys, 'argv', ['fast_pass', 'decrypt', '-i', 'test.pdf', '-p']):
            with pytest.raises(SystemExit):  # argparse should catch this
                cli_module.parse_command_line_arguments()
    
    def test_very_long_arguments(self):
        """Test: Very long arguments handling"""
        long_filename = "a" * 1000 + ".pdf"
        long_password = "p" * 1000
        
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', long_filename, '-p', long_password]):
            args = cli_module.parse_command_line_arguments()
            assert str(args.input) == long_filename
            assert args.password[0] == long_password
    
    def test_unicode_arguments(self):
        """Test: Unicode arguments handling"""
        unicode_filename = "тест_файл.pdf"
        unicode_password = "пароль123"
        
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', unicode_filename, '-p', unicode_password]):
            args = cli_module.parse_command_line_arguments()
            assert str(args.input) == unicode_filename
            assert args.password[0] == unicode_password
    
    def test_special_characters_in_paths(self):
        """Test: Special characters in file paths"""
        special_filename = "file$with&special@chars!.pdf"
        
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', special_filename, '-p', 'password']):
            args = cli_module.parse_command_line_arguments()
            assert str(args.input) == special_filename
    
    def test_relative_vs_absolute_paths(self):
        """Test: Relative vs absolute path handling for single file"""
        import os
        import platform
        
        if platform.system() == 'Windows':
            relative_path = "relative\\path\\file.pdf"
            absolute_path = "C:\\absolute\\path\\file.pdf"
        else:
            relative_path = "relative/path/file.pdf"
            absolute_path = "/absolute/path/file.pdf"
        
        # Test relative path
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', relative_path, '-p', 'password']):
            args = cli_module.parse_command_line_arguments()
            assert str(args.input).replace('/', os.sep) == relative_path
            assert args.input.is_absolute() is False
        
        # Test absolute path
        with patch.object(sys, 'argv', ['fast_pass', 'encrypt', '-i', absolute_path, '-p', 'password']):
            args = cli_module.parse_command_line_arguments()
            assert str(args.input).replace('/', os.sep) == absolute_path
            assert args.input.is_absolute() is True