# FastPass Comprehensive Test Design Document

## Overview

This document defines a comprehensive testing strategy for the FastPass CLI tool that ensures **100% coverage** of all functionality, edge cases, security features, and real-world usage scenarios. The testing approach follows enterprise-grade practices with automated unit tests, integration tests, and end-to-end tests.

**Testing Philosophy**: Test every single aspect of the program without exception. Every flowchart box, every function, every security validation, every user input scenario, and every error condition must be covered by automated tests.

---

## Test Directory Structure

```
tests/
├── conftest.py                     # PyTest configuration and shared fixtures
├── requirements.txt                # Test-specific dependencies
├── pytest.ini                     # PyTest settings and markers
├── test_runner.py                  # Main test execution script
├── 
├── unit/                           # Unit tests (isolated component testing)
│   ├── __init__.py
│   ├── test_cli_parsing.py         # CLI argument parsing and validation
│   ├── test_security_validation.py # Security hardening functions
│   ├── test_file_validation.py     # File format and path validation
│   ├── test_password_management.py # Password handling and memory security
│   ├── test_crypto_handlers.py     # Individual crypto tool integrations
│   ├── test_file_operations.py     # File processing and temporary management
│   ├── test_error_handling.py      # Exception handling and recovery
│   └── test_utilities.py           # Helper functions and utilities
│   
├── integration/                    # Integration tests (component interaction)
│   ├── __init__.py
│   ├── test_cli_to_processing.py   # Full CLI → Processing pipeline
│   ├── test_security_integration.py # Security validation integration
│   ├── test_password_workflows.py  # Password source integration
│   ├── test_file_workflows.py      # File processing workflows
│   └── test_error_propagation.py   # Error handling across components
│   
├── e2e/                            # End-to-end tests (full program execution)
│   ├── __init__.py
│   ├── test_encrypt_operations.py  # Real encryption operations
│   ├── test_decrypt_operations.py  # Real decryption operations
│   ├── test_check_password.py      # Password checking operations
│   ├── test_recursive_mode.py      # Recursive directory processing
│   ├── test_batch_operations.py    # Multiple file processing
│   ├── test_edge_cases.py          # Real-world edge cases
│   └── test_security_scenarios.py  # Security attack simulation
│   
├── fixtures/                       # Test data and sample files
│   ├── __init__.py
│   ├── sample_files/               # Clean test files for processing
│   │   ├── clean/                  # Unprotected sample files
│   │   │   ├── sample.docx
│   │   │   ├── sample.xlsx
│   │   │   ├── sample.pptx
│   │   │   ├── sample.pdf
│   │   │   ├── empty.docx
│   │   │   └── large_file.pdf
│   │   ├── protected/              # Pre-encrypted sample files
│   │   │   ├── password_123/       # Files encrypted with "123"
│   │   │   ├── password_complex/   # Files encrypted with complex passwords
│   │   │   └── password_special/   # Files with special character passwords
│   │   └── corrupted/              # Intentionally corrupted files
│   │       ├── truncated.docx
│   │       ├── malformed.pdf
│   │       └── zero_bytes.xlsx
│   ├── password_lists/             # Password list test files
│   │   ├── simple_passwords.txt
│   │   ├── complex_passwords.txt
│   │   ├── empty_passwords.txt
│   │   └── malformed_passwords.txt
│   ├── malicious/                  # Security test files
│   │   ├── path_traversal/         # Path traversal attack samples
│   │   ├── xxe_samples/            # XXE injection test files
│   │   ├── zip_bombs/              # ZIP bomb test files
│   │   └── oversized/              # Oversized file attacks
│   └── expected_outputs/           # Expected results for validation
│       ├── encryption_results/
│       ├── decryption_results/
│       └── error_messages/
│       
├── performance/                    # Performance and stress tests
│   ├── __init__.py
│   ├── test_large_files.py         # Large file processing performance
│   ├── test_batch_performance.py   # Batch operation performance
│   ├── test_memory_usage.py        # Memory consumption validation
│   └── test_concurrent_operations.py # Concurrent processing tests
│   
├── security/                       # Dedicated security tests
│   ├── __init__.py
│   ├── test_attack_vectors.py      # All security attack simulations
│   ├── test_path_traversal.py      # Path traversal attack prevention
│   ├── test_command_injection.py   # Command injection prevention
│   ├── test_password_security.py   # Password memory and exposure prevention
│   └── test_file_security.py       # File format attack prevention
│   
└── reports/                        # Test execution reports
    ├── coverage/                   # Code coverage reports
    ├── performance/                # Performance test results
    └── security/                   # Security test results
```

---

## Unit Test Coverage Plan

### **A. CLI Argument Parsing Tests** (`test_cli_parsing.py`)

**Complete coverage of every CLI scenario from flowchart:**

```python
class TestCLIArgumentParsing:
    """Test every CLI argument combination and validation"""
    
    # A1: Basic Command Structure Tests
    def test_encrypt_mode_basic(self):
        """Test: fast_pass encrypt -i file.docx -p password"""
        
    def test_decrypt_mode_basic(self):
        """Test: fast_pass decrypt -i file.docx -p password"""
        
    def test_check_password_mode(self):
        """Test: fast_pass check-password -i file.docx -p password"""
    
    # A2: Input File Specification Tests
    def test_single_file_input(self):
        """Test: -i single_file.docx"""
        
    def test_multiple_files_input(self):
        """Test: -i file1.docx file2.pdf file3.xlsx"""
        
    def test_files_with_spaces(self):
        """Test: -i "file with spaces.docx" "another file.pdf" """
        
    def test_mixed_paths_relative_absolute(self):
        """Test: -i /abs/path/file.docx relative/file.pdf"""
        
    def test_no_input_files_error(self):
        """Test: Missing -i flag should trigger error"""
    
    # A3: Password Specification Tests  
    def test_single_password_cli(self):
        """Test: -p password123"""
        
    def test_multiple_passwords_cli(self):
        """Test: -p password1 password2 "complex pass""""
        
    def test_password_with_spaces(self):
        """Test: -p "password with spaces" """
        
    def test_password_with_special_chars(self):
        """Test: -p "p@$$w0rd!" "another&password#""""
        
    def test_password_from_file(self):
        """Test: -p @passwords.txt"""
        
    def test_password_from_stdin_tty(self):
        """Test: -p stdin with TTY input"""
        
    def test_password_from_stdin_json(self):
        """Test: -p stdin with JSON input via pipe"""
        
    def test_no_password_error(self):
        """Test: Missing -p should trigger error"""
    
    # A4: Recursive Mode Tests
    def test_recursive_decrypt_allowed(self):
        """Test: fast_pass decrypt --recursive -p password"""
        
    def test_recursive_check_password_allowed(self):
        """Test: fast_pass check-password --recursive -p password"""
        
    def test_recursive_encrypt_blocked(self):
        """Test: fast_pass encrypt --recursive should trigger security error"""
    
    # A5: Security Flag Tests
    def test_allow_cwd_flag(self):
        """Test: --allow-cwd flag enables current directory processing"""
        
    def test_cwd_blocked_without_flag(self):
        """Test: CWD processing blocked without --allow-cwd"""
    
    # A6: Utility Flag Tests
    def test_dry_run_mode(self):
        """Test: --dry-run shows operations without execution"""
        
    def test_verify_mode(self):
        """Test: --verify enables deep verification"""
        
    def test_list_supported_formats(self):
        """Test: --list-supported shows format list and exits"""
        
    def test_debug_mode(self):
        """Test: --debug enables detailed logging"""
        
    def test_help_display(self):
        """Test: -h and --help show usage information"""
    
    # A7: Argument Validation Tests
    def test_invalid_operation_mode(self):
        """Test: Invalid operation should trigger error"""
        
    def test_conflicting_flags(self):
        """Test: Conflicting flag combinations should error"""
        
    def test_malformed_arguments(self):
        """Test: Malformed argument syntax should error"""
    
    # A8: Edge Case Argument Tests
    def test_empty_string_arguments(self):
        """Test: Empty string arguments should be handled gracefully"""
        
    def test_very_long_arguments(self):
        """Test: Extremely long arguments should be validated"""
        
    def test_unicode_arguments(self):
        """Test: Unicode in file paths and passwords"""
        
    def test_argument_injection_attempts(self):
        """Test: Command injection attempts in arguments should be blocked"""
```

### **B. Security Validation Tests** (`test_security_validation.py`)

**Test every security hardening feature:**

```python
class TestSecurityHardening:
    """Test all security validation functions"""
    
    # B1: Path Traversal Protection Tests
    def test_path_traversal_attack_prevention(self):
        """Test: ../../../etc/passwd blocked"""
        
    def test_symlink_attack_prevention(self):
        """Test: Symbolic link attacks blocked"""
        
    def test_absolute_path_containment(self):
        """Test: Paths must be within allowed directories"""
        
    def test_hidden_file_access_prevention(self):
        """Test: Hidden files (.secret) blocked"""
        
    def test_cwd_security_enforcement(self):
        """Test: CWD access requires --allow-cwd flag"""
    
    # B2: Command Injection Prevention Tests
    def test_filename_injection_prevention(self):
        """Test: file.docx; rm -rf / blocked"""
        
    def test_path_injection_prevention(self):
        """Test: Path components with shell metacharacters blocked"""
        
    def test_subprocess_safety(self):
        """Test: No shell execution with user input"""
    
    # B3: File Format Security Tests
    def test_magic_number_validation(self):
        """Test: File magic numbers validated against extensions"""
        
    def test_xxe_injection_prevention(self):
        """Test: XXE attacks in Office documents blocked"""
        
    def test_zip_bomb_detection(self):
        """Test: ZIP bomb compression ratios detected"""
        
    def test_oversized_file_rejection(self):
        """Test: Files exceeding size limits rejected"""
        
    def test_malformed_pdf_rejection(self):
        """Test: Malformed PDF attacks blocked"""
    
    # B4: Password Security Tests
    def test_password_memory_clearing(self):
        """Test: Password memory cleared after use"""
        
    def test_password_length_validation(self):
        """Test: Extremely long passwords handled securely"""
        
    def test_password_character_validation(self):
        """Test: Null bytes and control characters in passwords blocked"""
        
    def test_stdin_password_security(self):
        """Test: Stdin password input doesn't expose to process list"""
    
    # B5: File Access Security Tests
    def test_permission_validation(self):
        """Test: File permissions checked before processing"""
        
    def test_write_access_validation(self):
        """Test: Output directory write access validated"""
        
    def test_temp_file_security(self):
        """Test: Temporary files created with secure permissions (0o600)"""
        
    def test_atomic_file_operations(self):
        """Test: File operations are atomic to prevent race conditions"""
```

### **C. File Validation Tests** (`test_file_validation.py`)

**Test every file format and validation scenario:**

```python
class TestFileValidation:
    """Test all file format validation and detection"""
    
    # C1: File Format Detection Tests
    def test_docx_magic_number_detection(self):
        """Test: .docx files detected by magic number"""
        
    def test_xlsx_magic_number_detection(self):
        """Test: .xlsx files detected by magic number"""
        
    def test_pptx_magic_number_detection(self):
        """Test: .pptx files detected by magic number"""
        
    def test_pdf_magic_number_detection(self):
        """Test: .pdf files detected by magic number"""
    
    # C2: File Extension Validation Tests
    def test_supported_extension_validation(self):
        """Test: Only supported extensions (.docx, .xlsx, .pptx, .pdf) allowed"""
        
    def test_legacy_office_rejection(self):
        """Test: Legacy formats (.doc, .xls, .ppt) rejected"""
        
    def test_unsupported_format_rejection(self):
        """Test: Unsupported formats (.txt, .zip, .rar) rejected"""
    
    # C3: File Content Validation Tests
    def test_empty_file_rejection(self):
        """Test: Zero-byte files rejected"""
        
    def test_corrupted_file_detection(self):
        """Test: Corrupted files detected and rejected"""
        
    def test_file_size_limits(self):
        """Test: Files exceeding size limits rejected"""
        
    def test_truncated_file_detection(self):
        """Test: Truncated files detected"""
    
    # C4: Encryption Status Detection Tests
    def test_encrypted_office_detection(self):
        """Test: Password-protected Office documents detected"""
        
    def test_unencrypted_office_detection(self):
        """Test: Unprotected Office documents detected"""
        
    def test_encrypted_pdf_detection(self):
        """Test: Password-protected PDFs detected"""
        
    def test_unencrypted_pdf_detection(self):
        """Test: Unprotected PDFs detected"""
    
    # C5: Cross-Validation Tests
    def test_magic_vs_extension_mismatch(self):
        """Test: Magic number vs extension conflicts handled"""
        
    def test_renamed_file_detection(self):
        """Test: .pdf renamed to .docx detected correctly"""
        
    def test_forged_extension_detection(self):
        """Test: Malicious files with forged extensions detected"""
```

### **D. Password Management Tests** (`test_password_management.py`)

**Test all password handling scenarios:**

```python
class TestPasswordManagement:
    """Test password handling and security"""
    
    # D1: Password Source Tests
    def test_cli_password_parsing(self):
        """Test: CLI passwords parsed correctly"""
        
    def test_password_file_loading(self):
        """Test: Password list file loading"""
        
    def test_stdin_json_password_parsing(self):
        """Test: JSON password input via stdin"""
        
    def test_stdin_tty_password_input(self):
        """Test: Interactive password input"""
    
    # D2: Password List File Tests
    def test_password_file_format_validation(self):
        """Test: Password file format requirements"""
        
    def test_empty_password_file_handling(self):
        """Test: Empty password files handled gracefully"""
        
    def test_malformed_password_file_handling(self):
        """Test: Malformed password files trigger appropriate errors"""
        
    def test_password_file_encoding_support(self):
        """Test: UTF-8 encoded password files supported"""
    
    # D3: Password Security Tests
    def test_password_memory_management(self):
        """Test: Passwords cleared from memory after use"""
        
    def test_password_logging_prevention(self):
        """Test: Passwords never appear in logs"""
        
    def test_password_process_list_prevention(self):
        """Test: Passwords don't appear in process list"""
        
    def test_secure_password_comparison(self):
        """Test: Password comparison uses secure methods"""
    
    # D4: Password Validation Tests
    def test_password_attempt_with_files(self):
        """Test: Passwords attempted against files in correct order"""
        
    def test_working_password_identification(self):
        """Test: Working password identified and cached"""
        
    def test_failed_password_handling(self):
        """Test: Failed passwords handled gracefully"""
        
    def test_password_exhaustion_handling(self):
        """Test: Behavior when all passwords fail"""
```

### **E. Crypto Handler Tests** (`test_crypto_handlers.py`)

**Test each crypto tool integration:**

```python
class TestCryptoHandlers:
    """Test crypto tool integrations"""
    
    # E1: Office Handler Tests
    def test_office_encryption_success(self):
        """Test: Office document encryption with msoffcrypto-tool"""
        
    def test_office_decryption_success(self):
        """Test: Office document decryption with msoffcrypto-tool"""
        
    def test_office_password_check(self):
        """Test: Office document password verification"""
        
    def test_office_wrong_password_handling(self):
        """Test: Wrong password for Office document handled"""
        
    def test_office_experimental_encryption_warning(self):
        """Test: Experimental encryption warning displayed"""
    
    # E2: PDF Handler Tests
    def test_pdf_encryption_success(self):
        """Test: PDF encryption with PyPDF2"""
        
    def test_pdf_decryption_success(self):
        """Test: PDF decryption with PyPDF2"""
        
    def test_pdf_password_check(self):
        """Test: PDF password verification"""
        
    def test_pdf_wrong_password_handling(self):
        """Test: Wrong password for PDF handled"""
        
    def test_pdf_permission_handling(self):
        """Test: PDF permission restrictions handled"""
    
    # E3: Handler Selection Tests
    def test_handler_selection_by_format(self):
        """Test: Correct handler selected based on file format"""
        
    def test_handler_availability_check(self):
        """Test: Handler availability checked before processing"""
        
    def test_missing_handler_error(self):
        """Test: Missing crypto tool triggers appropriate error"""
    
    # E4: Tool Integration Error Tests
    def test_msoffcrypto_tool_errors(self):
        """Test: msoffcrypto-tool errors handled gracefully"""
        
    def test_pypdf2_errors(self):
        """Test: PyPDF2 errors handled gracefully"""
        
    def test_tool_compatibility_validation(self):
        """Test: Tool version compatibility checked"""
```

---

## Integration Test Coverage Plan

### **F. CLI to Processing Pipeline Tests** (`test_cli_to_processing.py`)

**Test complete workflows from CLI input to final output:**

```python
class TestCLIProcessingIntegration:
    """Test full CLI → Processing pipeline integration"""
    
    def test_encrypt_single_file_workflow(self):
        """Test: Complete encrypt workflow for single file"""
        
    def test_decrypt_single_file_workflow(self):
        """Test: Complete decrypt workflow for single file"""
        
    def test_check_password_workflow(self):
        """Test: Complete password check workflow"""
        
    def test_multiple_file_processing_workflow(self):
        """Test: Multiple files processed in sequence"""
        
    def test_password_list_integration_workflow(self):
        """Test: Password list file integration with processing"""
        
    def test_error_recovery_workflow(self):
        """Test: Error recovery in multi-file processing"""
```

---

## End-to-End Test Coverage Plan

### **G. Real File Operations Tests** (`test_encrypt_operations.py`, `test_decrypt_operations.py`)

**Test actual file encryption/decryption with real files:**

```python
class TestRealEncryptionOperations:
    """Test real encryption operations with actual files"""
    
    # G1: Single File Encryption Tests
    def test_encrypt_docx_real_file(self):
        """Test: Encrypt real .docx file, verify result can be opened with password"""
        
    def test_encrypt_xlsx_real_file(self):
        """Test: Encrypt real .xlsx file, verify result can be opened with password"""
        
    def test_encrypt_pptx_real_file(self):
        """Test: Encrypt real .pptx file, verify result can be opened with password"""
        
    def test_encrypt_pdf_real_file(self):
        """Test: Encrypt real .pdf file, verify result can be opened with password"""
    
    # G2: Encryption Verification Tests
    def test_encrypted_file_requires_password(self):
        """Test: Encrypted file cannot be opened without password"""
        
    def test_encrypted_file_opens_with_correct_password(self):
        """Test: Encrypted file opens successfully with correct password"""
        
    def test_encrypted_file_rejects_wrong_password(self):
        """Test: Encrypted file rejects incorrect password"""
        
    def test_encryption_preserves_content(self):
        """Test: File content identical after encrypt→decrypt cycle"""
    
    # G3: Batch Encryption Tests
    def test_encrypt_multiple_files_same_password(self):
        """Test: Multiple files encrypted with same password"""
        
    def test_encrypt_multiple_files_different_passwords(self):
        """Test: Multiple files encrypted with different passwords each"""
        
    def test_encrypt_mixed_formats_batch(self):
        """Test: Mixed file formats encrypted in single batch"""

class TestRealDecryptionOperations:
    """Test real decryption operations with actual encrypted files"""
    
    # G4: Single File Decryption Tests
    def test_decrypt_docx_real_file(self):
        """Test: Decrypt real encrypted .docx file"""
        
    def test_decrypt_xlsx_real_file(self):
        """Test: Decrypt real encrypted .xlsx file"""
        
    def test_decrypt_pptx_real_file(self):
        """Test: Decrypt real encrypted .pptx file"""
        
    def test_decrypt_pdf_real_file(self):
        """Test: Decrypt real encrypted .pdf file"""
    
    # G5: Decryption Verification Tests
    def test_decrypted_file_no_password_required(self):
        """Test: Decrypted file opens without password"""
        
    def test_decryption_preserves_content(self):
        """Test: Decrypted content matches original"""
        
    def test_decryption_with_wrong_password_fails(self):
        """Test: Decryption fails with wrong password"""
        
    def test_decryption_preserves_formatting(self):
        """Test: Document formatting preserved after decryption"""
    
    # G6: Password List Decryption Tests
    def test_decrypt_with_password_list(self):
        """Test: Decryption using password list file"""
        
    def test_decrypt_password_list_exhaustion(self):
        """Test: Behavior when password list exhausted"""
        
    def test_decrypt_password_list_mixed_success(self):
        """Test: Some files decrypt, others fail with password list"""
```

### **H. Complex Scenario Tests** (`test_batch_operations.py`, `test_edge_cases.py`)

**Test real-world usage scenarios:**

```python
class TestComplexRealWorldScenarios:
    """Test complex real-world usage scenarios"""
    
    # H1: Multi-File Multi-Password Scenarios
    def test_office_documents_different_passwords(self):
        """
        Test: Process 5 Office documents, each with different passwords
        - sample1.docx (password: "doc123")
        - sample2.xlsx (password: "sheet456") 
        - sample3.pptx (password: "slide789")
        - sample4.docx (password: "complex&password!")
        - sample5.pdf (password: "pdf#secure@2024")
        """
        
    def test_password_reuse_across_files(self):
        """
        Test: Multiple files using same password from CLI list
        - 3 files encrypted with "shared123"
        - 2 files encrypted with "common456"
        - CLI: -p shared123 common456
        """
        
    def test_mixed_encrypted_unencrypted_batch(self):
        """
        Test: Batch with mix of encrypted and unencrypted files
        - 2 files already encrypted
        - 3 files unencrypted
        - Different passwords for each encrypted file
        """
    
    # H2: Password List File Scenarios
    def test_password_list_priority_order(self):
        """
        Test: Password list file with 10 passwords, verify order
        - File with password #7 in list
        - Verify passwords 1-6 attempted first
        - Verify password #7 succeeds
        - Verify passwords 8-10 not attempted
        """
        
    def test_password_list_with_special_characters(self):
        """
        Test: Password list containing special characters
        - Passwords with spaces: "my password 123"
        - Passwords with symbols: "p@$$w0rd#2024!"
        - Unicode passwords: "пароль123"
        """
    
    # H3: File Path Edge Cases
    def test_files_with_spaces_in_names(self):
        """
        Test: Files with spaces in names and paths
        - "My Important Document.docx"
        - "Q3 Financial Report.xlsx"
        - "Project Presentation Final.pptx"
        """
        
    def test_long_file_paths(self):
        """
        Test: Very long file paths (approaching system limits)
        - Nested directory structure 10+ levels deep
        - File names with maximum allowed length
        """
        
    def test_unicode_file_names(self):
        """
        Test: Unicode characters in file names
        - Chinese characters: "文档.docx"
        - Emoji: "📊 Report.xlsx"
        - Accented characters: "Café Menu.pdf"
        """
    
    # H4: Recursive Mode Real Tests
    def test_recursive_decrypt_directory_tree(self):
        """
        Test: Recursive decryption of directory tree
        - 3 levels deep directory structure
        - 15 encrypted files across all levels
        - Mixed file formats
        - Different passwords per directory level
        """
        
    def test_recursive_check_password_comprehensive(self):
        """
        Test: Recursive password check across directory tree
        - 20 files across multiple directories
        - 5 different passwords used
        - Mixed protected/unprotected files
        - Verify correct password identified for each file
        """
    
    # H5: Error Recovery Scenarios
    def test_partial_failure_recovery(self):
        """
        Test: Some files succeed, others fail in batch
        - 10 files in batch
        - 3 files have wrong passwords
        - 2 files are corrupted
        - 5 files process successfully
        - Verify successful files completed, failed files reported
        """
        
    def test_disk_space_exhaustion_handling(self):
        """
        Test: Behavior when disk space runs out during processing
        - Large files that fill available disk space
        - Verify graceful failure and cleanup
        """
        
    def test_permission_denied_recovery(self):
        """
        Test: Handle files with insufficient permissions
        - Read-only files
        - Files owned by other users
        - Files in protected directories
        """
```

### **I. Security Attack Simulation Tests** (`test_security_scenarios.py`)

**Test actual security attack scenarios:**

```python
class TestSecurityAttackSimulation:
    """Test real security attack scenarios"""
    
    # I1: Path Traversal Attack Tests
    def test_path_traversal_attack_real(self):
        """
        Test: Real path traversal attack attempts
        - Input: -i "../../../etc/passwd"
        - Input: -i "..\\..\\Windows\\System32\\config\\SAM"
        - Verify: All attempts blocked with security errors
        """
        
    def test_symlink_attack_real(self):
        """
        Test: Real symbolic link attack
        - Create symlink pointing to /etc/passwd
        - Attempt to process via FastPass
        - Verify: Attack blocked, symlink detected
        """
    
    # I2: Command Injection Attack Tests
    def test_filename_injection_attack_real(self):
        """
        Test: Real command injection via filename
        - Input: -i "file.docx; rm -rf /tmp/*"
        - Input: -i "file.pdf && cat /etc/passwd"
        - Verify: Commands not executed, filenames sanitized
        """
        
    def test_password_injection_attack_real(self):
        """
        Test: Real command injection via password
        - Input: -p "password; cat /etc/passwd"
        - Input: -p "pass && rm file.txt"
        - Verify: Commands not executed, passwords handled safely
        """
    
    # I3: File Format Attack Tests
    def test_xxe_injection_attack_real(self):
        """
        Test: Real XXE injection attack
        - Malicious .docx with XXE payload
        - XXE attempting to read local files
        - Verify: Attack blocked, XXE entities disabled
        """
        
    def test_zip_bomb_attack_real(self):
        """
        Test: Real ZIP bomb attack
        - Office document containing ZIP bomb
        - Extremely high compression ratio
        - Verify: ZIP bomb detected and blocked
        """
        
    def test_oversized_file_attack_real(self):
        """
        Test: Real oversized file attack
        - Files exceeding configured size limits
        - Memory exhaustion attempts
        - Verify: Large files rejected before processing
        """
    
    # I4: Password Security Attack Tests
    def test_password_memory_dump_simulation(self):
        """
        Test: Simulate password memory exposure
        - Process files with passwords
        - Attempt to read password from memory dumps
        - Verify: Passwords cleared from memory
        """
        
    def test_process_list_password_exposure(self):
        """
        Test: Verify passwords don't appear in process list
        - Run FastPass with passwords
        - Check ps/tasklist output for password exposure
        - Verify: Passwords not visible in process arguments
        """
```

---

## Performance and Stress Tests

### **J. Performance Validation Tests** (`test_large_files.py`, `test_batch_performance.py`)

```python
class TestPerformanceValidation:
    """Test performance requirements and limits"""
    
    # J1: Large File Performance Tests
    def test_large_pdf_processing_performance(self):
        """
        Test: Process 100MB PDF file
        - Requirement: Complete within 30 seconds
        - Verify: Memory usage stays within reasonable limits
        """
        
    def test_large_office_document_performance(self):
        """
        Test: Process 50MB Office document
        - Requirement: Complete within 20 seconds
        - Verify: Temporary file cleanup within 5 seconds
        """
    
    # J2: Batch Processing Performance Tests
    def test_batch_processing_100_files(self):
        """
        Test: Process 100 small files in batch
        - Requirement: All files processed within 60 seconds
        - Verify: Memory usage scales linearly
        """
        
    def test_concurrent_file_processing(self):
        """
        Test: Multiple FastPass instances running simultaneously
        - Run 5 FastPass processes concurrently
        - Verify: No file corruption or interference
        """
    
    # J3: Memory Usage Tests
    def test_memory_usage_large_batches(self):
        """
        Test: Memory usage with large file batches
        - Process 50 files of 10MB each
        - Verify: Memory usage < 1GB total
        - Verify: Memory released after each file
        """
        
    def test_memory_leak_detection(self):
        """
        Test: Detect memory leaks in long-running operations
        - Process 1000 small files sequentially
        - Monitor memory usage throughout
        - Verify: No continuous memory growth
        """
```

---

## Test Execution Framework

### **Test Configuration** (`conftest.py`)

```python
"""PyTest configuration and shared fixtures"""

import pytest
import tempfile
import shutil
from pathlib import Path
import subprocess
import os

@pytest.fixture(scope="session")
def test_data_dir():
    """Fixture providing test data directory"""
    return Path(__file__).parent / "fixtures"

@pytest.fixture(scope="session") 
def sample_files_dir(test_data_dir):
    """Fixture providing sample files directory"""
    return test_data_dir / "sample_files"

@pytest.fixture
def temp_work_dir():
    """Fixture providing temporary working directory for each test"""
    temp_dir = tempfile.mkdtemp(prefix="fastpass_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def fastpass_executable():
    """Fixture providing path to FastPass executable"""
    # Assuming FastPass is installed or available in PATH
    return "fast_pass"

@pytest.fixture 
def encrypted_test_files(sample_files_dir, temp_work_dir):
    """Fixture providing pre-encrypted test files"""
    # Copy sample files to temp directory and encrypt them
    encrypted_files = {}
    
    sample_file = sample_files_dir / "clean" / "sample.docx"
    encrypted_file = temp_work_dir / "sample_encrypted.docx"
    
    # Use subprocess to encrypt with known password
    subprocess.run([
        "fast_pass", "encrypt", 
        "-i", str(sample_file),
        "-p", "test123",
        "--output", str(encrypted_file)
    ], check=True)
    
    encrypted_files["docx"] = {
        "file": encrypted_file,
        "password": "test123"
    }
    
    return encrypted_files

@pytest.fixture
def password_list_file(temp_work_dir):
    """Fixture providing password list file"""
    password_file = temp_work_dir / "passwords.txt"
    passwords = [
        "password123",
        "secret456", 
        "complex&password!",
        "test with spaces",
        "паролъ123"  # Unicode password
    ]
    
    with open(password_file, 'w', encoding='utf-8') as f:
        for password in passwords:
            f.write(f"{password}\n")
    
    return password_file

# Performance test markers
pytest.mark.performance = pytest.mark.mark("performance", "Performance tests")
pytest.mark.security = pytest.mark.mark("security", "Security tests")  
pytest.mark.e2e = pytest.mark.mark("e2e", "End-to-end tests")
pytest.mark.integration = pytest.mark.mark("integration", "Integration tests")
```

### **Test Execution Script** (`test_runner.py`)

```python
#!/usr/bin/env python3
"""
FastPass Test Runner
Executes comprehensive test suite with reporting
"""

import subprocess
import sys
import time
from pathlib import Path

def run_test_suite():
    """Run complete test suite with coverage reporting"""
    
    print("🚀 Starting FastPass Comprehensive Test Suite")
    print("=" * 60)
    
    start_time = time.time()
    
    # Test execution order
    test_phases = [
        ("Unit Tests", "tests/unit/"),
        ("Integration Tests", "tests/integration/"), 
        ("End-to-End Tests", "tests/e2e/"),
        ("Security Tests", "tests/security/"),
        ("Performance Tests", "tests/performance/")
    ]
    
    total_results = {
        "passed": 0,
        "failed": 0,
        "skipped": 0
    }
    
    for phase_name, test_dir in test_phases:
        print(f"\n📋 Running {phase_name}")
        print("-" * 40)
        
        cmd = [
            "python", "-m", "pytest",
            test_dir,
            "-v",
            "--tb=short", 
            "--cov=fastpass",
            "--cov-report=html:reports/coverage/",
            "--junit-xml=reports/junit.xml",
            "--html=reports/test_report.html"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ {phase_name} PASSED")
            else:
                print(f"❌ {phase_name} FAILED")
                print(result.stdout)
                print(result.stderr)
                
        except Exception as e:
            print(f"💥 {phase_name} ERROR: {e}")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n🏁 Test Suite Complete")
    print(f"⏱️  Total Duration: {duration:.2f} seconds")
    print(f"📊 Coverage Report: reports/coverage/index.html")
    print(f"📋 Test Report: reports/test_report.html")

if __name__ == "__main__":
    run_test_suite()
```

---

## Test Data Management

### **Sample File Creation Script** (`fixtures/create_sample_files.py`)

```python
#!/usr/bin/env python3
"""
Create comprehensive sample files for testing
"""

import os
from pathlib import Path
import shutil
from docx import Document
import openpyxl
from pptx import Presentation
from reportlab.pdfgen import canvas

def create_sample_files():
    """Create all required sample files for testing"""
    
    fixtures_dir = Path(__file__).parent
    clean_dir = fixtures_dir / "sample_files" / "clean"
    clean_dir.mkdir(parents=True, exist_ok=True)
    
    # Create sample DOCX
    doc = Document()
    doc.add_heading('Test Document', 0)
    doc.add_paragraph('This is a test document for FastPass testing.')
    doc.add_paragraph('It contains multiple paragraphs for validation.')
    doc.save(clean_dir / "sample.docx")
    
    # Create sample XLSX
    wb = openpyxl.Workbook()
    ws = wb.active
    ws['A1'] = 'Test Data'
    ws['A2'] = 'Value 1'
    ws['A3'] = 'Value 2'
    wb.save(clean_dir / "sample.xlsx")
    
    # Create sample PPTX
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[0])
    title = slide.shapes.title
    subtitle = slide.placeholders[1]
    title.text = "Test Presentation"
    subtitle.text = "FastPass Testing Sample"
    prs.save(clean_dir / "sample.pptx")
    
    # Create sample PDF
    pdf_path = clean_dir / "sample.pdf"
    c = canvas.Canvas(str(pdf_path))
    c.drawString(100, 750, "Test PDF Document")
    c.drawString(100, 730, "This is a sample PDF for FastPass testing.")
    c.save()
    
    print("✅ Sample files created successfully")

if __name__ == "__main__":
    create_sample_files()
```

---

## Test Quality Assurance

### **Test Coverage Requirements**

- **Minimum Code Coverage**: 95% line coverage
- **Branch Coverage**: 90% branch coverage  
- **Function Coverage**: 100% function coverage
- **Security Test Coverage**: 100% of attack vectors tested

### **Test Performance Requirements**

- **Unit Tests**: All unit tests complete within 30 seconds
- **Integration Tests**: All integration tests complete within 2 minutes
- **End-to-End Tests**: All E2E tests complete within 10 minutes
- **Full Suite**: Complete test suite finishes within 15 minutes

### **Test Data Requirements**

- **Sample Files**: Representative files for each supported format
- **Encrypted Files**: Pre-encrypted files with known passwords
- **Malicious Files**: Security test files for attack simulation
- **Edge Case Files**: Files testing format limits and edge cases

### **Continuous Integration Integration**

```yaml
# .github/workflows/test.yml
name: FastPass Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r tests/requirements.txt
    
    - name: Run test suite
      run: python tests/test_runner.py
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v1
```

---

## Summary

This comprehensive test design provides **exhaustive coverage** of the FastPass application:

**✅ Complete Coverage**:
- Every CLI argument combination
- Every security hardening feature  
- Every file format and validation scenario
- Every password handling method
- Every crypto tool integration
- Every error condition and recovery scenario

**✅ Real-World Testing**:
- Actual file encryption/decryption operations
- Multi-file batch processing scenarios
- Complex password list workflows
- Performance validation with large files
- Security attack simulation with real payloads

**✅ Automated Execution**:
- Pytest framework with comprehensive fixtures
- Automated test data generation
- Performance monitoring and reporting
- Coverage analysis and reporting
- CI/CD integration ready

**✅ Quality Assurance**:
- 95% minimum code coverage requirement
- All tests complete within 15 minutes
- Comprehensive error scenario testing
- Security attack vector validation

The test suite ensures FastPass reliability, security, and performance meet enterprise-grade standards while maintaining rapid automated execution for continuous integration.