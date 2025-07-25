# FastPass - Core Business Logic Flow

This document focuses on the essential file processing workflow - how files are handled, where they're copied, and how final output is created.

## High-Level Processing Flow

```mermaid
flowchart TD
    Start([User: fast_pass decrypt file1.pdf file2.docx -p "password"]) --> Parse[Parse CLI Arguments]
    Parse --> FileList[Build File Processing List]
    FileList --> TempSetup[Create Secure Temp Directory]
    TempSetup --> Backup[Create Backup Files]
    Backup --> Process[Process Each File Through Crypto Pipeline]
    Process --> Validate[Validate Processing Success]
    Validate --> FinalOutput[Move to Final Output Location]
    FinalOutput --> Cleanup[Cleanup Temp Files]
    Cleanup --> Complete([Processing Complete])
    
    classDef coreProcess fill:#e8f5e8,stroke:#4caf50,stroke-width:2px
    class Parse,FileList,TempSetup,Backup,Process,Validate,FinalOutput,Cleanup coreProcess
```

## File Processing Pipeline

### 1. File List Preparation

**Input Processing:**
```python
# Multiple password approaches supported:

# 1. Per-file passwords: fast_pass decrypt file1.pdf -p "pwd1" file2.docx -p "pwd2"
file_processing_list = [
    {'path': Path('file1.pdf'), 'specific_password': 'pwd1', 'format': 'pdf'},
    {'path': Path('file2.docx'), 'specific_password': 'pwd2', 'format': 'office'}
]

# 2. Multiple passwords: fast_pass decrypt files*.pdf -p "pwd1" -p "pwd2" -p "pwd3"
password_candidates = ['pwd1', 'pwd2', 'pwd3']  # Try all on each file

# 3. Password list file: fast_pass decrypt files*.pdf --password-list passwords.txt
# passwords.txt contains:
# password123
# secret456
# admin789

# 4. Combined: fast_pass decrypt files*.pdf -p "urgent" --password-list common.txt
password_priority = [
    'urgent',           # CLI passwords first
    'password123',      # Then password list file
    'secret456', 
    'admin789',
    'previous_success'  # Finally password reuse pool
]
```

**Tool Assignment:**
```python
tool_mapping = {
    '.pdf': 'PyPDF2',
    '.docx': 'msoffcrypto', '.xlsx': 'msoffcrypto', '.pptx': 'msoffcrypto',
    '.zip': 'pyzipper', '.7z': 'pyzipper'
}
```

### 2. File Layout Structure

**Backup Location (Optional --backup flag):**
```
/documents/                    # Original file location
├── report.pdf                 # Original file
├── report_backup_20250125_143022.pdf    # In-place backup (if --backup)
└── spreadsheet.xlsx
└── spreadsheet_backup_20250125_143022.xlsx
```

**Temporary Directory Structure:**
```
/temp/FastPass_20250125_143022_1234/
├── processing/        # Input files copied here FIRST before any crypto operations
│   ├── temp_abc123_report.pdf
│   ├── temp_def456_spreadsheet.xlsx
│   └── temp_ghi789_archive.zip
└── output/           # Final processed files before move back
    ├── report_decrypted.pdf
    ├── spreadsheet_decrypted.xlsx  
    └── archive_decrypted.zip
```

### 3. File Processing Workflow

```mermaid
flowchart TD
    FileInput[Input File] --> CheckBackup{--backup flag set?}
    CheckBackup -->|Yes| CreateBackup[Create In-Place Backup]
    CheckBackup -->|No| MoveToTemp[Copy Input File to temp/processing/]
    CreateBackup --> MoveToTemp
    
    MoveToTemp --> DetectFormat[Detect File Format from temp copy]
    DetectFormat --> RouteToHandler{Route to Crypto Handler}
    
    RouteToHandler -->|PDF| PDFProcess[PyPDF2 Processing on temp file]
    RouteToHandler -->|Office| OfficeProcess[msoffcrypto Processing on temp file]
    RouteToHandler -->|ZIP| ZipProcess[pyzipper Processing on temp file]
    
    PDFProcess --> TempOutput[Write result to temp/output/]
    OfficeProcess --> TempOutput
    ZipProcess --> TempOutput
    
    TempOutput --> ValidateOutput[Validate Processing Success]
    ValidateOutput --> FinalLocation[Move from temp/output/ to original location]
    
    classDef processStep fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef backupStep fill:#fff3e0,stroke:#ff9800,stroke-width:2px
    class DetectFormat,TempOutput,ValidateOutput,FinalLocation processStep
    class CreateBackup,MoveToTemp backupStep
```

### 4. Crypto Processing Details

#### PDF Processing (PyPDF2)
```python
def process_pdf_file(input_path, temp_output, password, operation):
    import PyPDF2
    
    if operation == 'decrypt':
        with open(input_path, 'rb') as input_file:
            reader = PyPDF2.PdfReader(input_file)
            if reader.is_encrypted:
                reader.decrypt(password)
            writer = PyPDF2.PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            with open(temp_output, 'wb') as output_file:
                writer.write(output_file)
    
    elif operation == 'encrypt':
        with open(input_path, 'rb') as input_file:
            reader = PyPDF2.PdfReader(input_file)
            writer = PyPDF2.PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.encrypt(password)
            with open(temp_output, 'wb') as output_file:
                writer.write(output_file)
```

#### Office Document Processing (msoffcrypto)
```python
def process_office_file(input_path, temp_output, password, operation):
    import msoffcrypto
    
    with open(input_path, 'rb') as input_file:
        office_file = msoffcrypto.OfficeFile(input_file)
        
        if operation == 'decrypt':
            office_file.load_key(password=password)
            with open(temp_output, 'wb') as output_file:
                office_file.decrypt(output_file)
        
        elif operation == 'encrypt':
            office_file.encrypt(password=password, output_file=temp_output)
```

#### ZIP Processing (pyzipper)
```python
def process_zip_file(input_path, temp_output, password, operation):
    import pyzipper
    import zipfile
    
    if operation == 'decrypt':
        # Extract encrypted ZIP to unencrypted ZIP
        with pyzipper.AESZipFile(input_path) as encrypted_zf:
            encrypted_zf.setpassword(password.encode('utf-8'))
            with zipfile.ZipFile(temp_output, 'w') as unencrypted_zf:
                for file_info in encrypted_zf.infolist():
                    file_data = encrypted_zf.read(file_info.filename)
                    unencrypted_zf.writestr(file_info.filename, file_data)
    
    elif operation == 'encrypt':
        # Create encrypted ZIP from input files
        with pyzipper.AESZipFile(temp_output, 'w', compression=pyzipper.ZIP_DEFLATED) as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            zf.write(input_path, input_path.name)
```

### 5. Output File Placement

#### In-Place Modification (Default)
```python
# Original: /documents/report.pdf
# Backup:   /documents/report_backup_20250125_143022.pdf (if --backup)
# Temp:     /temp/processing/temp_abc123_report.pdf (input copy)
# Process:  /temp/output/report_decrypted.pdf (processed result)
# Final:    /documents/report.pdf (overwrites original)

# All operations are temp-based, then moved back
final_path = original_file_path
shutil.move(temp_processed_file, final_path)
```

#### Output Directory Mode
```python
# Original: /documents/report.pdf
# Output:   /decrypted/report.pdf (original unchanged)

if args.output_dir:
    final_path = Path(args.output_dir) / processed_file_name
    final_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(temp_processed_file, final_path)
```

#### Conflict Resolution
```python
# If target exists, append counter
if final_path.exists():
    stem = final_path.stem
    suffix = final_path.suffix
    counter = 1
    while final_path.exists():
        final_path = final_path.parent / f"{stem}_{counter:03d}{suffix}"
        counter += 1
```

### 6. File Tracking Throughout Process

```python
class FileTracker:
    def __init__(self):
        self.file_operations = []
    
    def track_file(self, original_path, operation):
        file_record = {
            'original_path': Path(original_path),
            'backup_path': None,
            'temp_path': None, 
            'final_path': None,
            'operation': operation,
            'status': 'pending',
            'crypto_tool': None
        }
        self.file_operations.append(file_record)
        return file_record
    
    def update_paths(self, record, backup_path=None, temp_path=None, final_path=None):
        if backup_path:
            record['backup_path'] = Path(backup_path)
        if temp_path:
            record['temp_path'] = Path(temp_path)
        if final_path:
            record['final_path'] = Path(final_path)
```

### 7. Password Selection Algorithm

```python
def get_passwords_for_file(file_path, specific_password=None):
    """Get prioritized list of passwords to try for a file"""
    candidates = []
    
    # Priority 1: Per-file specific password (highest priority)
    if specific_password and specific_password != 'stdin':
        candidates.append(specific_password)
        
    # Priority 2: CLI -p passwords (in order provided)  
    candidates.extend(cli_passwords)  # From multiple -p flags
    
    # Priority 3: Password list file (line by line)
    if password_list_file:
        candidates.extend(load_password_list())
        
    # Priority 4: Password reuse pool (successful passwords from previous files)
    if password_reuse_enabled:
        candidates.extend(reversed(password_pool))  # Most recent first
        
    # Remove duplicates while preserving order
    return list(dict.fromkeys(candidates))

# Example usage:
# fast_pass decrypt file1.pdf -p "specific" -p "common1" -p "common2" --password-list list.txt
#
# For file1.pdf, password order will be:
# 1. "specific" (per-file)
# 2. "common1" (CLI)  
# 3. "common2" (CLI)
# 4. "password123" (from list.txt)
# 5. "secret456" (from list.txt)
# 6. "previous_success" (from password reuse pool if enabled)
```

### 8. Batch Processing Flow

```mermaid
flowchart TD
    BatchStart[Multiple Files Input] --> Sequential{Process Sequentially}
    Sequential --> File1[Process File 1]
    File1 --> File1Success{Success?}
    File1Success -->|Yes| File2[Process File 2]
    File1Success -->|No| MarkFailed1[Mark File 1 as Failed]
    MarkFailed1 --> File2
    
    File2 --> File2Success{Success?}
    File2Success -->|Yes| File3[Process File 3]
    File2Success -->|No| MarkFailed2[Mark File 2 as Failed]
    MarkFailed2 --> File3
    
    File3 --> ContinueOrComplete[Continue for all files...]
    ContinueOrComplete --> Report[Generate Results Report]
    
    Report --> ReportFormat[Report Format:<br/>✓ file1.pdf - Success<br/>✗ file2.docx - Wrong password<br/>✓ file3.zip - Success]
    
    classDef success fill:#e8f5e8,stroke:#4caf50,stroke-width:2px
    classDef failure fill:#ffebee,stroke:#f44336,stroke-width:2px
    classDef process fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    
    class File1,File2,File3 process
    class MarkFailed1,MarkFailed2 failure
    class ReportFormat success
```

### 8. Results and Cleanup

**Success Case:**
```python
# All files processed successfully
final_results = {
    'total_files': 3,
    'successful': 3,
    'failed': 0,
    'output_files': [
        '/documents/report.pdf',           # Processed file (overwrote original)
        '/documents/spreadsheet.xlsx',      # Processed file  
        '/documents/archive.zip'            # Processed file
    ],
    'backups_created': [                    # In-place backups (if --backup used)
        '/documents/report_backup_20250125_143022.pdf',
        '/documents/spreadsheet_backup_20250125_143022.xlsx',
        '/documents/archive_backup_20250125_143022.zip'
    ]
}

# Cleanup: Remove temp directory (originals restored from temp processing)
shutil.rmtree(temp_working_dir)
```

**Partial Failure Case:**
```python
# Some files failed processing
final_results = {
    'total_files': 3,
    'successful': 2,
    'failed': 1,
    'successful_files': ['/documents/report.pdf', '/documents/archive.zip'],
    'failed_files': [{'file': '/documents/spreadsheet.xlsx', 'error': 'Wrong password'}],
    'backups_available': [
        '/documents/report_backup_20250125_143022.pdf',      # Successful processing, backup remains
        '/documents/spreadsheet_backup_20250125_143022.xlsx', # Failed processing, original unchanged
        '/documents/archive_backup_20250125_143022.zip'       # Successful processing, backup remains
    ]
}

# Cleanup: Remove temp directory, failed files remain unchanged, backups remain in-place
shutil.rmtree(temp_working_dir)
```

## Key Design Principles

1. **File Isolation**: All processing happens in secure temporary directories, never on originals
2. **Backup Visibility**: Optional in-place backups are created in same directory as originals for easy access
3. **Temp-First Processing**: Files are copied to temp directory BEFORE any crypto operations
4. **Atomic Operations**: Each file is processed completely in temp, then moved to final location
5. **Progress Continuation**: Failures on one file don't stop processing of others  
6. **Password Flexibility**: Multiple password sources with clear priority algorithm
7. **Clean Recovery**: Failed operations leave originals unchanged, backups provide recovery
8. **Predictable Output**: Output file locations follow consistent patterns
9. **Resource Cleanup**: Temporary files are always cleaned up after processing

This workflow ensures data safety while providing efficient batch processing of mixed file types with flexible password handling and visible backup management.