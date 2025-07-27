# E2E Test Suite Design - FastPass Encryption/Decryption

## Overview
Replace existing E2E tests with focused encryption and decryption tests that use real file fixtures and verify results with raw tools (PyPDF2 and msoffcrypto).

## Test Structure

### Test Organization
- **Location**: `/tests/e2e/test_complete_workflows.py`
- **Approach**: Individual test functions per file type and operation
- **Verification**: Raw tool validation of encryption status + FastPass check-password command validation

### File Fixtures
- **Encrypted files**: `c:\Dev\fast_pass\tests\fixtures\sample_files\encrypted\`
- **Decrypted files**: `c:\Dev\fast_pass\tests\fixtures\sample_files\decrypted\`
- **Password**: All encrypted files use "test123"

## Encryption Tests

### Test Coverage
Create individual tests for each modern format that supports encryption:

1. `test_encrypt_docx()` - Word documents
2. `test_encrypt_xlsx()` - Excel spreadsheets  
3. `test_encrypt_pptx()` - PowerPoint presentations
4. `test_encrypt_pdf()` - PDF documents

### Test Logic for Each Encryption Test
```python
def test_encrypt_[format]():
    # 1. Setup temporary output directory
    # 2. Get source file from fixtures/sample_files/decrypted/
    # 3. Run FastPass encrypt command via subprocess
    # 4. Verify FastPass reports success (return code 0)
    # 5. Use raw tool to check output file encryption status
    # 6. Assert: is_encrypted == True
    # 7. Cleanup temporary files
```

### Raw Tool Verification (Encryption)
- **Office files (.docx, .xlsx, .pptx)**: `msoffcrypto.OfficeFile(f).is_encrypted()`
- **PDF files (.pdf)**: `PyPDF2.PdfReader(f).is_encrypted`

## Decryption Tests

### Test Coverage
Create individual tests for all supported formats (including legacy):

1. `test_decrypt_docx()` - Word documents (modern)
2. `test_decrypt_xlsx()` - Excel spreadsheets (modern)
3. `test_decrypt_pptx()` - PowerPoint presentations (modern)
4. `test_decrypt_pdf()` - PDF documents
5. `test_decrypt_doc()` - Word documents (legacy)
6. `test_decrypt_xls()` - Excel spreadsheets (legacy)
7. `test_decrypt_ppt()` - PowerPoint presentations (legacy)

### Test Logic for Each Decryption Test
```python
def test_decrypt_[format]():
    # 1. Setup temporary output directory
    # 2. Get source file from fixtures/sample_files/encrypted/
    # 3. Run FastPass decrypt command via subprocess
    # 4. Verify FastPass reports success (return code 0)
    # 5. Use raw tool to check output file encryption status
    # 6. Assert: is_encrypted == False
    # 7. Cleanup temporary files
```

### Raw Tool Verification (Decryption)
- **Office files**: `msoffcrypto.OfficeFile(f).is_encrypted()` should return `False`
- **PDF files**: `PyPDF2.PdfReader(f).is_encrypted` should return `False`

## Test Implementation Details

### FastPass Command Execution
```python
import subprocess
import tempfile
from pathlib import Path

# Example encryption command
result = subprocess.run([
    "python", "main.py", "encrypt",
    "--input", str(input_file),
    "--output", str(output_file),
    "--password", "test123"
], capture_output=True, text=True, cwd=fastpass_root)
```

### Raw Tool Integration
```python
import PyPDF2
import msoffcrypto

def verify_pdf_encryption_status(file_path):
    with open(file_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        return reader.is_encrypted

def verify_office_encryption_status(file_path):
    with open(file_path, 'rb') as f:
        office_file = msoffcrypto.OfficeFile(f)
        return office_file.is_encrypted()
```

### Expected Behavior

#### Encryption Tests (4 tests)
- **Input**: Decrypted files from fixtures
- **Expected**: FastPass success + raw tool reports `is_encrypted=True`
- **Formats**: DOCX, XLSX, PPTX, PDF

#### Decryption Tests (7 tests)
- **Input**: Encrypted files from fixtures  
- **Expected**: FastPass success + raw tool reports `is_encrypted=False`
- **Formats**: DOCX, XLSX, PPTX, PDF, DOC, XLS, PPT

## Password Checking Tests

### Check-Password on Decrypted Files (7 tests)
Test that check-password correctly identifies unencrypted files:

1. `test_check_password_decrypted_docx()` - Should report `password_protected=False`
2. `test_check_password_decrypted_xlsx()` - Should report `password_protected=False`
3. `test_check_password_decrypted_pptx()` - Should report `password_protected=False`
4. `test_check_password_decrypted_pdf()` - Should report `password_protected=False`
5. `test_check_password_decrypted_doc()` - Should report `password_protected=False`
6. `test_check_password_decrypted_xls()` - Should report `password_protected=False`
7. `test_check_password_decrypted_ppt()` - Should report `password_protected=False`

### Check-Password on Encrypted Files (7 tests)
Test that check-password correctly identifies encrypted files:

1. `test_check_password_encrypted_docx()` - Should report `password_protected=True`
2. `test_check_password_encrypted_xlsx()` - Should report `password_protected=True`
3. `test_check_password_encrypted_pptx()` - Should report `password_protected=True`
4. `test_check_password_encrypted_pdf()` - Should report `password_protected=True`
5. `test_check_password_encrypted_doc()` - Should report `password_protected=True`
6. `test_check_password_encrypted_xls()` - Should report `password_protected=True`
7. `test_check_password_encrypted_ppt()` - Should report `password_protected=True`

### Check-Password with Correct Password (7 tests)
Test that check-password validates correct passwords on encrypted files:

1. `test_check_password_correct_docx()` - Should report `password_correct=True` for "test123"
2. `test_check_password_correct_xlsx()` - Should report `password_correct=True` for "test123"
3. `test_check_password_correct_pptx()` - Should report `password_correct=True` for "test123"
4. `test_check_password_correct_pdf()` - Should report `password_correct=True` for "test123"
5. `test_check_password_correct_doc()` - Should report `password_correct=True` for "test123"
6. `test_check_password_correct_xls()` - Should report `password_correct=True` for "test123"
7. `test_check_password_correct_ppt()` - Should report `password_correct=True` for "test123"

### Check-Password with Wrong Password (7 tests)
Test that check-password identifies incorrect passwords on encrypted files:

1. `test_check_password_wrong_docx()` - Should report `password_protected=True, password_correct=False` for "test345"
2. `test_check_password_wrong_xlsx()` - Should report `password_protected=True, password_correct=False` for "test345"
3. `test_check_password_wrong_pptx()` - Should report `password_protected=True, password_correct=False` for "test345"
4. `test_check_password_wrong_pdf()` - Should report `password_protected=True, password_correct=False` for "test345"
5. `test_check_password_wrong_doc()` - Should report `password_protected=True, password_correct=False` for "test345"
6. `test_check_password_wrong_xls()` - Should report `password_protected=True, password_correct=False` for "test345"
7. `test_check_password_wrong_ppt()` - Should report `password_protected=True, password_correct=False` for "test345"

### Password Check Command Examples
```python
# Check if file is password protected (no password provided)
result = subprocess.run([
    "python", "main.py", "check-password",
    "--input", str(input_file)
], capture_output=True, text=True, cwd=fastpass_root)

# Check if specific password is correct
result = subprocess.run([
    "python", "main.py", "check-password", 
    "--input", str(input_file),
    "--password", "test123"
], capture_output=True, text=True, cwd=fastpass_root)
```

### Expected Check-Password Output Parsing
The tests will need to parse FastPass output to determine:
- **Password protection status**: Whether file is encrypted
- **Password correctness**: Whether provided password is valid
- **Exit codes**: Success/failure status of the operation

### Known Issues to Test
- **Legacy format decryption**: May fail with `'NoneType' encoding error` (should be captured in tests)
- **Modern format support**: Should work reliably for DOCX/XLSX/PPTX/PDF
- **Exit codes**: Need to verify FastPass has distinct exit codes for different password check scenarios

## Complete Test Suite Summary

### Total Test Count: 39 Tests

#### Encryption Tests (4 tests)
- Modern formats only: DOCX, XLSX, PPTX, PDF

#### Decryption Tests (7 tests)  
- All supported formats: DOCX, XLSX, PPTX, PDF, DOC, XLS, PPT

#### Password Check Tests (28 tests)
- **Decrypted files** (7 tests): Verify `password_protected=False`
- **Encrypted files** (7 tests): Verify `password_protected=True` 
- **Correct password** (7 tests): Verify `password_correct=True` with "test123"
- **Wrong password** (7 tests): Verify `password_protected=True, password_correct=False` with "test345"

## Test Benefits

1. **Real file validation**: Uses actual file fixtures instead of generated content
2. **Independent verification**: Raw tools provide objective encryption status
3. **True E2E testing**: Full subprocess execution of FastPass CLI
4. **Format coverage**: Tests all supported file types individually
5. **Clear pass/fail criteria**: Binary encryption status check
6. **Comprehensive password validation**: Tests all password check scenarios
7. **Exit code validation**: Verifies proper error handling and status reporting

## File Structure
```
tests/
├── e2e/
│   └── test_complete_workflows.py  # All new tests here
├── fixtures/
│   └── sample_files/
│       ├── encrypted/              # Source files for decryption tests
│       │   ├── sample.docx (encrypted, pw: test123)
│       │   ├── sample.xlsx (encrypted, pw: test123)
│       │   ├── sample.pptx (encrypted, pw: test123)
│       │   ├── sample.pdf (encrypted, pw: test123)
│       │   ├── sample.doc (encrypted, pw: test123)
│       │   ├── sample.xls (encrypted, pw: test123)
│       │   └── sample.ppt (encrypted, pw: test123)
│       └── decrypted/              # Source files for encryption tests
│           ├── sample.docx (decrypted)
│           ├── sample.xlsx (decrypted)
│           ├── sample.pptx (decrypted)
│           └── sample.pdf (decrypted)
```

This design provides comprehensive E2E testing with objective verification using the same raw tools that were used to validate our manual testing.