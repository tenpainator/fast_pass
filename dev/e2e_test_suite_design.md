# E2E Test Suite Design - FastPass Encryption/Decryption

## Overview
Replace existing E2E tests with focused encryption and decryption tests that use real file fixtures and verify results with raw tools (PyPDF2 and msoffcrypto).

## Test Structure

### Test Organization
- **Location**: `/tests/e2e/test_complete_workflows.py`
- **Approach**: Individual test functions per file type and operation
- **Verification**: Raw tool validation of encryption status

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

### Known Issues to Test
- **Legacy format decryption**: May fail with `'NoneType' encoding error` (should be captured in tests)
- **Modern format support**: Should work reliably for DOCX/XLSX/PPTX/PDF

## Test Benefits

1. **Real file validation**: Uses actual file fixtures instead of generated content
2. **Independent verification**: Raw tools provide objective encryption status
3. **True E2E testing**: Full subprocess execution of FastPass CLI
4. **Format coverage**: Tests all supported file types individually
5. **Clear pass/fail criteria**: Binary encryption status check

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