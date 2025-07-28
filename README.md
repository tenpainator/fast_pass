# FastPass

**Universal file encryption and decryption tool for Microsoft Office documents and PDFs**

FastPass provides a simple, secure way to add or remove password protection from your documents through both command-line and Python library interfaces. It supports modern Microsoft Office formats (.docx, .xlsx, .pptx) and PDF files with enterprise-grade security practices.

## Quick Start

### Installation

```bash
pip install fastpass
```

### Basic Usage

```bash
# Encrypt a document
fastpass encrypt -i contract.docx -p "mypassword"

# Decrypt a document
fastpass decrypt -i encrypted.pdf -p "password123"

# Check if a file is password-protected
fastpass check -i document.xlsx
```

## Command Line Interface

### Commands

FastPass provides three main commands:

- **`encrypt`** - Add password protection to files
- **`decrypt`** - Remove password protection from files
- **`check`** - Check if files require passwords

### Basic Syntax

```bash
fastpass {encrypt|decrypt|check} -i FILE [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-i, --input FILE` | File to process (required) |
| `-p, --password PWD...` | Password(s) to use (multiple passwords supported) |
| `-o, --output-dir DIR` | Output directory (default: modify file in-place) |
| `--debug` | Enable detailed logging |
| `-h, --help` | Show help and supported formats |
| `--version` | Show version information |

### Supported File Formats

| Format | Encrypt | Decrypt | Check | Notes |
|--------|---------|---------|-------|-------|
| `.pdf` | ✅ | ✅ | ✅ | Full support |
| `.docx` | ✅ | ✅ | ✅ | Modern Office documents |
| `.xlsx` | ✅ | ✅ | ✅ | Modern Excel workbooks |
| `.pptx` | ✅ | ✅ | ✅ | Modern PowerPoint presentations |
| `.docm` | ✅ | ✅ | ✅ | Macro-enabled Word documents |
| `.xlsm` | ✅ | ✅ | ✅ | Macro-enabled Excel workbooks |
| `.pptm` | ✅ | ✅ | ✅ | Macro-enabled PowerPoint |
| `.dotx` | ✅ | ✅ | ✅ | Word templates |
| `.xltx` | ✅ | ✅ | ✅ | Excel templates |
| `.potx` | ✅ | ✅ | ✅ | PowerPoint templates |
| `.doc` | ❌ | ✅ | ✅ | Legacy Word (decrypt only) |
| `.xls` | ❌ | ✅ | ✅ | Legacy Excel (decrypt only) |
| `.ppt` | ❌ | ✅ | ✅ | Legacy PowerPoint (decrypt only) |

### CLI Examples

#### Basic Operations

```bash
# Encrypt a Word document
fastpass encrypt -i report.docx -p "secret123"

# Encrypt with output to different directory
fastpass encrypt -i contract.pdf -p "mypassword" -o ./encrypted/

# Decrypt a password-protected file
fastpass decrypt -i encrypted.xlsx -p "password123"

# Check if a file is password-protected
fastpass check -i document.pdf
```

#### Multiple Password Attempts

```bash
# Try multiple passwords for decryption
fastpass decrypt -i locked.pdf -p "password1" "password2" "backup_pwd"

# Check with password verification
fastpass check -i document.docx -p "testpassword"
```

#### Files with Spaces in Names

```bash
# Use quotes for file paths with spaces
fastpass encrypt -i "My Important Document.docx" -p "secret"
fastpass decrypt -i "Project Files/Report 2024.pdf" -p "password"
```

#### Automation with JSON Password Arrays

```bash
# Read passwords from JSON array via stdin
echo '["pwd1", "pwd2", "pwd3"]' | fastpass decrypt -i file.pdf -p stdin

# Combine CLI passwords with stdin passwords
echo '["backup_pwd"]' | fastpass decrypt -i file.pdf -p "main_pwd" stdin

# Use literal "stdin" as a password (quoted)
fastpass decrypt -i file.pdf -p "stdin"
```

#### Debugging

```bash
# Enable detailed logging (saves to temp directory)
fastpass encrypt -i document.docx -p "password" --debug
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (file access, processing failure) |
| 2 | Invalid arguments or command syntax |
| 3 | Security violation (invalid file path, unsupported format) |
| 4 | Password error (wrong password, authentication failure) |

## Python Library Interface

FastPass can be used as a Python library for programmatic file encryption and decryption.

### Installation for Library Use

```bash
pip install fastpass
```

### Basic Library Usage

#### Object-Oriented Interface

```python
from fastpass import DocumentProcessor

# Use as context manager (recommended)
with DocumentProcessor() as processor:
    # Encrypt a file
    result = processor.encrypt_file("contract.docx", "mypassword")
    if result.success:
        print(f"Successfully encrypted: {result.input_file}")
        print(f"Output location: {result.output_file}")
    else:
        print(f"Encryption failed: {result.error_message}")
    
    # Decrypt a file with multiple password attempts
    result = processor.decrypt_file("encrypted.pdf", ["pwd1", "pwd2", "pwd3"])
    if result.success:
        print(f"Successfully decrypted with password: {result.password_used}")
    
    # Check if file is password-protected
    is_protected = processor.is_password_protected("document.xlsx")
    print(f"File is password-protected: {is_protected}")
```

#### Convenience Functions

```python
from fastpass import encrypt_file, decrypt_file, is_password_protected

# Simple encryption
result = encrypt_file("report.docx", "secret123")
if result.success:
    print("File encrypted successfully!")

# Simple decryption with multiple passwords
result = decrypt_file("encrypted.pdf", ["password1", "password2"])
if result.success:
    print(f"Decrypted with password: {result.password_used}")

# Check password protection status
protected = is_password_protected("document.xlsx")
print(f"Password protected: {protected}")
```

### Library API Reference

#### DocumentProcessor Class

The main class for programmatic file operations.

```python
class DocumentProcessor:
    def __enter__(self) -> 'DocumentProcessor'
    def __exit__(self, exc_type, exc_val, exc_tb) -> None
    
    def encrypt_file(self, file_path: str, password: str, 
                    output_dir: str = None) -> ProcessingResult
    
    def decrypt_file(self, file_path: str, passwords: List[str], 
                    output_dir: str = None) -> ProcessingResult
    
    def is_password_protected(self, file_path: str) -> bool
```

##### Methods

**`encrypt_file(file_path, password, output_dir=None)`**
- Encrypts a file with the specified password
- `file_path`: Path to the file to encrypt
- `password`: Password to use for encryption
- `output_dir`: Optional output directory (default: in-place)
- Returns: `ProcessingResult` object

**`decrypt_file(file_path, passwords, output_dir=None)`**
- Decrypts a file using the provided password(s)
- `file_path`: Path to the encrypted file
- `passwords`: List of passwords to try
- `output_dir`: Optional output directory (default: in-place)
- Returns: `ProcessingResult` object

**`is_password_protected(file_path)`**
- Checks if a file is password-protected
- `file_path`: Path to the file to check
- Returns: `bool` (True if password-protected)

#### ProcessingResult Class

Result object returned by processing operations.

```python
class ProcessingResult:
    success: bool                    # True if operation succeeded
    input_file: str                  # Original input file path
    output_file: str                 # Output file path (may be same as input)
    operation: str                   # Operation performed ('encrypt'/'decrypt')
    password_used: str               # Password that worked (decrypt only)
    processing_time: float           # Time taken in seconds
    error_message: str               # Error description if failed
```

#### Convenience Functions

**`encrypt_file(file_path, password, output_dir=None)`**
- Standalone function for quick encryption
- Returns: `ProcessingResult`

**`decrypt_file(file_path, passwords, output_dir=None)`**
- Standalone function for quick decryption
- `passwords`: Can be a string (single password) or list of strings
- Returns: `ProcessingResult`

**`is_password_protected(file_path)`**
- Standalone function to check password protection
- Returns: `bool`

### Advanced Library Examples

#### Batch Processing

```python
from fastpass import DocumentProcessor
import os

files_to_encrypt = ["report1.docx", "report2.xlsx", "presentation.pptx"]
password = "company_secret_2024"

with DocumentProcessor() as processor:
    results = []
    for file_path in files_to_encrypt:
        if os.path.exists(file_path):
            result = processor.encrypt_file(file_path, password, output_dir="./encrypted/")
            results.append(result)
            
            if result.success:
                print(f"✅ {file_path} encrypted successfully")
            else:
                print(f"❌ {file_path} failed: {result.error_message}")
    
    successful = sum(1 for r in results if r.success)
    print(f"Encrypted {successful}/{len(results)} files")
```

#### Password Recovery

```python
from fastpass import DocumentProcessor

# Try common passwords for a locked file
common_passwords = [
    "password", "123456", "admin", "user", 
    "company2024", "secret", "password123"
]

with DocumentProcessor() as processor:
    result = processor.decrypt_file("locked_document.pdf", common_passwords)
    
    if result.success:
        print(f"Successfully unlocked with password: {result.password_used}")
        print(f"Processing time: {result.processing_time:.2f} seconds")
    else:
        print("Could not unlock file with any of the provided passwords")
```

#### File Analysis

```python
from fastpass import DocumentProcessor
import os

def analyze_directory(directory_path):
    """Analyze all supported files in a directory for password protection."""
    
    supported_extensions = ['.pdf', '.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt']
    results = {"protected": [], "unprotected": [], "errors": []}
    
    with DocumentProcessor() as processor:
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            
            if any(filename.lower().endswith(ext) for ext in supported_extensions):
                try:
                    is_protected = processor.is_password_protected(file_path)
                    if is_protected:
                        results["protected"].append(filename)
                    else:
                        results["unprotected"].append(filename)
                except Exception as e:
                    results["errors"].append(f"{filename}: {str(e)}")
    
    return results

# Usage
results = analyze_directory("./documents/")
print(f"Protected files: {len(results['protected'])}")
print(f"Unprotected files: {len(results['unprotected'])}")
print(f"Errors: {len(results['errors'])}")
```

#### Error Handling

```python
from fastpass import DocumentProcessor, ProcessingResult

def safe_encrypt(file_path: str, password: str) -> bool:
    """Safely encrypt a file with comprehensive error handling."""
    
    try:
        with DocumentProcessor() as processor:
            result = processor.encrypt_file(file_path, password)
            
            if result.success:
                print(f"Successfully encrypted {file_path}")
                print(f"Output: {result.output_file}")
                return True
            else:
                print(f"Encryption failed: {result.error_message}")
                return False
                
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return False
    except PermissionError:
        print(f"Permission denied accessing: {file_path}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return False

# Usage
success = safe_encrypt("important_document.pdf", "secure_password_2024")
```

## Security Features

- **Path Traversal Protection**: Restricts file operations to safe directories
- **Input Validation**: Validates all file paths and formats before processing
- **Secure Temporary Files**: Creates temporary files with restricted permissions (0o600)
- **Password Security**: Clears passwords from memory after use
- **Error Sanitization**: Prevents information disclosure through error messages
- **File Format Validation**: Uses magic number detection for format verification

## Troubleshooting

### Common Issues

**"ModuleNotFoundError: No module named 'fastpass'"**
- Ensure FastPass is installed: `pip install fastpass`
- Try reinstalling: `pip uninstall fastpass && pip install fastpass`

**"File not found" errors**
- Use absolute paths or ensure you're in the correct directory
- Use quotes around file paths with spaces: `"My Document.docx"`

**"Permission denied" errors**
- Ensure you have read/write permissions for the file and directory
- Check if the file is open in another application

**"Unsupported format" errors**
- Verify the file format is supported (see format table above)
- Ensure the file is not corrupted

**Password-related errors**
- Verify the password is correct
- For automation, ensure JSON password arrays are properly formatted
- Try multiple passwords: `-p "pwd1" "pwd2" "pwd3"`

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
fastpass encrypt -i document.pdf -p "password" --debug
```

Debug logs are automatically saved to your system's temporary directory with timestamps.

### Getting Help

```bash
# Show help with format support table
fastpass --help

# Show version information
fastpass --version
```

## Performance

FastPass is optimized for typical business documents:

- **Small files** (< 1MB): ~0.1 seconds
- **Medium files** (1-10MB): ~0.5 seconds  
- **Large files** (10-100MB): ~2-5 seconds
- **Maximum file size**: 500MB

Processing times may vary based on system performance and file complexity.