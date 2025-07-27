# FastPass AutoHotkey Integration

## Overview
This AutoHotkey v2 script provides quick Windows Explorer integration for FastPass, allowing you to encrypt/decrypt files with a simple keyboard shortcut.

## Requirements
- AutoHotkey v2 (download from https://www.autohotkey.com/)
- FastPass project installed in `c:\Dev\fast_pass`
- Windows Explorer (for file selection)

## Installation
1. Install AutoHotkey v2 if not already installed
2. Double-click `FastPassQuickToggle.ahk` to run the script
3. The script will show a confirmation message when loaded

## Usage

### Basic Operation
1. **Select a file** in Windows Explorer (single click to highlight it)
2. **Press Ctrl+Alt+4** to trigger FastPass operation
3. **Follow the prompts** to encrypt or decrypt the file

### Workflow Details

#### For Encrypted Files:
1. Script detects file is encrypted
2. Shows message box: "File is encrypted. Enter password to decrypt"
3. User enters password
4. If correct: File is decrypted in-place
5. If incorrect: Prompts for password again

#### For Unencrypted Files:
1. Script detects file is unencrypted  
2. Shows message box: "File is not encrypted. Enter password to encrypt"
3. User enters password
4. File is encrypted in-place with that password

### Supported File Types
- PDF files (.pdf)
- Microsoft Word documents (.docx, .doc)
- Microsoft Excel spreadsheets (.xlsx, .xls)  
- Microsoft PowerPoint presentations (.pptx, .ppt)

## Technical Details

### How It Works
1. **File Detection**: Uses COM objects to get selected file from active Explorer window
2. **Status Check**: Runs `python -m src check-password -i "file"` to determine encryption status
3. **Processing**: Runs `python -m src encrypt/decrypt -i "file" -p "password"` for operations
4. **User Feedback**: Shows message boxes for status updates and password prompts

### Command Line Integration
The script executes these FastPass commands:
```batch
# Check encryption status
python -m src check-password -i "filename.pdf"

# Encrypt file
python -m src encrypt -i "filename.pdf" -p "password"

# Decrypt file  
python -m src decrypt -i "filename.pdf" -p "password"
```

### Error Handling
- **No file selected**: Shows error message
- **Unsupported file type**: Shows format error
- **Wrong password**: Prompts again (recursive)
- **FastPass errors**: Shows generic error message

## Security Notes

⚠️ **This is a Proof of Concept script with the following limitations:**
- Passwords are **not masked** during input (visible as you type)
- No password confirmation prompts
- Command line arguments may be visible in process list
- Intended for **testing and demonstration only**

For production use, consider:
- Using secure password input methods
- Implementing password confirmation
- Adding command line obfuscation
- Enhanced error handling and logging

## Troubleshooting

### Script Doesn't Load
- Ensure AutoHotkey v2 is installed (not v1)
- Right-click script → "Run Script" if double-click doesn't work

### Hotkey Doesn't Work
- Ensure script is running (check system tray)
- Try selecting file again before pressing Ctrl+Alt+4
- Check that another program isn't using same hotkey

### "No file selected" Error
- Click once on a file in Explorer to select it
- Make sure Explorer window is active
- Try refreshing Explorer (F5) and selecting again

### "Unsupported file format" Error  
- Only PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT files are supported
- Check file extension is correct

### FastPass Command Errors
- Verify FastPass is installed in `c:\Dev\fast_pass`
- Check that Python and dependencies are available
- Run `test_integration.bat "filepath"` to test manually

## Customization

### Changing the Hotkey
Edit line 5 in the script:
```autohotkey
^!4::FastPassQuickToggle()  ; Current: Ctrl+Alt+4
^!e::FastPassQuickToggle()  ; Example: Ctrl+Alt+E  
F12::FastPassQuickToggle()  ; Example: F12 key
```

### Changing FastPass Directory
Edit line 53 in the script:
```autohotkey
fastPassPath := "c:\Dev\fast_pass"  ; Change this path
```

### Adding File Types
Edit the `IsSupportedFile()` function around line 32:
```autohotkey
supportedExts := ["pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "odt"]  ; Add formats
```

## Example Usage Session

1. **User opens Windows Explorer**
2. **Navigates to folder with contract.pdf**
3. **Clicks once on contract.pdf to select it**
4. **Presses Ctrl+Alt+4**
5. **Script shows: "File 'contract.pdf' is not encrypted. Enter password to encrypt:"**
6. **User types: "MySecret123"**
7. **Script runs encryption and shows: "File successfully encrypted!"**
8. **User presses Ctrl+Alt+4 again**
9. **Script shows: "File 'contract.pdf' is encrypted. Enter password to decrypt:"**
10. **User types: "MySecret123"**
11. **Script runs decryption and shows: "File successfully decrypted!"**

This provides a seamless Windows integration for FastPass file operations.