; FastPass File Explorer Integration - AutoHotkey v2
; Hotkeys for encrypting, decrypting, and checking files directly from File Explorer
; Author: FastPass Integration Script
; Version: 1.0

; Initialize log file
logFile := A_ScriptDir . "\fastpass_debug.log"
WriteLog("=== FastPass AHK Script Started ===")
WriteLog("Script Directory: " . A_ScriptDir)
WriteLog("Log File: " . logFile)
WriteLog("Time: " . A_Now)

; Only activate hotkeys when File Explorer is active
#HotIf WinActive("ahk_class CabinetWClass") || WinActive("ahk_class ExploreWClass")

; Ctrl+Alt+D: Decrypt file (check if encrypted, prompt for password, decrypt in-place)
^!d::
{
    selectedFile := GetSelectedFile()
    if (!selectedFile) {
        MsgBox("No file selected in File Explorer.", "FastPass - Error")
        return
    }
    
    ; Check if file is encrypted
    encryptionStatus := CheckFileEncryption(selectedFile)
    
    if (encryptionStatus == "error") {
        MsgBox("Error checking file encryption status.", "FastPass - Error")
        return
    }
    
    if (encryptionStatus == "not_encrypted") {
        MsgBox("File is not encrypted.", "FastPass - Info")
        return
    }
    
    if (encryptionStatus == "encrypted") {
        ; Prompt for password
        password := InputBox("Enter password to decrypt the file:", "FastPass - Decrypt", "Password").Value
        if (password == "") {
            MsgBox("Operation cancelled - no password provided.", "FastPass - Cancelled")
            return
        }
        
        ; Decrypt the file in-place
        result := DecryptFile(selectedFile, password)
        if (result == "success") {
            MsgBox("File decrypted successfully!", "FastPass - Success")
        } else {
            MsgBox("Failed to decrypt file. Please check the password and try again.", "FastPass - Error")
        }
    }
}

; Ctrl+Alt+E: Encrypt file (check if not encrypted, prompt for password, encrypt in-place)
^!e::
{
    selectedFile := GetSelectedFile()
    if (!selectedFile) {
        MsgBox("No file selected in File Explorer.", "FastPass - Error")
        return
    }
    
    ; Check if file is encrypted
    encryptionStatus := CheckFileEncryption(selectedFile)
    
    if (encryptionStatus == "error") {
        MsgBox("Error checking file encryption status.", "FastPass - Error")
        return
    }
    
    if (encryptionStatus == "encrypted") {
        MsgBox("File is already encrypted.", "FastPass - Info")
        return
    }
    
    if (encryptionStatus == "not_encrypted") {
        ; Check if file format is supported before prompting for password
        if (!IsFileFormatSupported(selectedFile)) {
            SplitPath(selectedFile, &fileName, , &ext)
            MsgBox("File format '" . ext . "' is not supported for encryption.`n`nSupported formats: .pdf, .docx, .xlsx, .pptx, .potx, .docm, .xlsm, .pptm, .dotx, .xltx", "FastPass - Unsupported Format")
            return
        }
        
        ; Prompt for password
        password := InputBox("Enter password to encrypt the file:", "FastPass - Encrypt", "Password").Value
        if (password == "") {
            MsgBox("Operation cancelled - no password provided.", "FastPass - Cancelled")
            return
        }
        
        ; Encrypt the file in-place
        result := EncryptFile(selectedFile, password)
        if (result == "success") {
            MsgBox("File encrypted successfully!", "FastPass - Success")
        } else {
            MsgBox("Failed to encrypt file. Please check the file format and try again.", "FastPass - Error")
        }
    }
}

; Ctrl+Alt+H: Check file encryption status (report only)
^!h::
{
    WriteLog("=== HOTKEY CTRL+ALT+H PRESSED ===")
    
    selectedFile := GetSelectedFile()
    if (!selectedFile) {
        WriteLog("ERROR: No file selected in File Explorer")
        MsgBox("No file selected in File Explorer. Check debug log: " . logFile, "FastPass - Error")
        return
    }
    
    WriteLog("Selected file: " . selectedFile)
    
    ; Check if file is encrypted
    encryptionStatus := CheckFileEncryption(selectedFile)
    WriteLog("Encryption status result: " . encryptionStatus)
    
    if (encryptionStatus == "error") {
        WriteLog("ERROR: Error checking file encryption status")
        MsgBox("Error checking file encryption status. Check debug log: " . logFile, "FastPass - Error")
        return
    }
    
    fileName := ""
    SplitPath(selectedFile, &fileName)
    
    if (encryptionStatus == "encrypted") {
        WriteLog("SUCCESS: File is encrypted")
        MsgBox("File '" . fileName . "' is ENCRYPTED.", "FastPass - Status Check")
    } else if (encryptionStatus == "not_encrypted") {
        WriteLog("SUCCESS: File is not encrypted")
        MsgBox("File '" . fileName . "' is NOT ENCRYPTED.", "FastPass - Status Check")
    }
    
    WriteLog("=== HOTKEY CTRL+ALT+H COMPLETED ===`n")
}

#HotIf  ; End context-sensitive hotkeys

; Function to get the selected file from File Explorer
GetSelectedFile() {
    WriteLog("--- GetSelectedFile() started ---")
    
    try {
        ; Get the active File Explorer window
        hwnd := WinGetID("A")
        WriteLog("Window HWND: " . hwnd)
        
        ; Create Shell Application COM object
        shell := ComObject("Shell.Application")
        WriteLog("Created Shell COM object successfully")
        
        ; Find the window in Shell.Windows collection
        windowCount := 0
        for window in shell.Windows {
            windowCount++
            WriteLog("Checking window " . windowCount . " (HWND: " . window.HWND . ")")
            
            if (window.HWND == hwnd) {
                WriteLog("Found matching window (Window " . windowCount . ")")
                
                ; Get selected items
                selectedItems := window.Document.SelectedItems()
                itemCount := selectedItems.Count
                WriteLog("Selected items count: " . itemCount)
                
                if (selectedItems.Count > 0) {
                    ; Return the path of the first selected item
                    filePath := selectedItems.Item(0).Path
                    WriteLog("COM Method found file: " . filePath)
                    WriteLog("--- GetSelectedFile() completed via COM ---")
                    return filePath
                }
                break
            }
        }
        WriteLog("Checked " . windowCount . " windows, no match found")
        
    } catch as err {
        WriteLog("COM method failed - Error: " . err.Message . " (Line: " . err.Line . ")")
        
        ; Fallback method using clipboard
        try {
            WriteLog("Trying clipboard fallback method")
            
            ; Save current clipboard
            oldClipboard := A_Clipboard
            A_Clipboard := ""
            
            ; Copy selected file path
            Send("^c")
            WriteLog("Sent Ctrl+C to copy selection")
            
            ; Wait for clipboard to contain data
            if (ClipWait(2)) {
                filePath := A_Clipboard
                WriteLog("Clipboard contents: " . filePath)
                
                ; Restore clipboard
                A_Clipboard := oldClipboard
                
                ; Verify it's a file path (not directory)
                fileExists := FileExist(filePath)
                dirExists := DirExist(filePath)
                WriteLog("FileExist: " . (fileExists ? "YES" : "NO") . ", DirExist: " . (dirExists ? "YES" : "NO"))
                
                if (fileExists && !dirExists) {
                    WriteLog("Clipboard method found valid file")
                    WriteLog("--- GetSelectedFile() completed via clipboard ---")
                    return filePath
                } else {
                    WriteLog("Clipboard path validation failed")
                }
            } else {
                WriteLog("ClipWait failed - nothing copied")
                ; Restore clipboard if copy failed
                A_Clipboard := oldClipboard
            }
        } catch as fallbackErr {
            WriteLog("Fallback method also failed - Error: " . fallbackErr.Message . " (Line: " . fallbackErr.Line . ")")
        }
    }
    
    WriteLog("GetSelectedFile returning empty string")
    WriteLog("--- GetSelectedFile() completed with no result ---")
    return ""
}

; Function to check if a file is encrypted using FastPass
CheckFileEncryption(filePath) {
    WriteLog("--- CheckFileEncryption() started ---")
    WriteLog("File Path: " . filePath)
    
    try {
        ; Change to FastPass directory
        fastPassDir := A_ScriptDir
        WriteLog("FastPass Dir: " . fastPassDir)
        WriteLog("File Exists: " . (FileExist(filePath) ? "YES" : "NO"))
        
        ; Build the command using main.py (the working entry point)
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python main.py check -i "' . filePath . '""'
        WriteLog("Initial command: " . cmd)
        
        ; Capture the output by redirecting to temp file
        tempFile := A_Temp . "\fastpass_check_" . A_TickCount . ".txt"
        
        ; Use the working main.py entry point
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python main.py check -i "' . filePath . '" > "' . tempFile . '" 2>&1"'
        WriteLog("Command with redirect: " . cmd)
        WriteLog("Temp file: " . tempFile)
        
        WriteLog("Executing command...")
        result := RunWait(cmd, fastPassDir, "Hide")
        WriteLog("Command execution completed")
        WriteLog("Return Code: " . result)
        WriteLog("Temp file exists: " . (FileExist(tempFile) ? "YES" : "NO"))
        
        ; Read the output
        if (FileExist(tempFile)) {
            output := FileRead(tempFile)
            WriteLog("Command output length: " . StrLen(output) . " characters")
            WriteLog("Command output content: " . output)
            
            ; Clean up temp file
            try {
                FileDelete(tempFile)
                WriteLog("Temp file deleted successfully")
            } catch as delErr {
                WriteLog("Failed to delete temp file: " . delErr.Message)
            }
            
            ; Parse the output to determine encryption status
            WriteLog("Parsing output for encryption status...")
            
            ; Check for "not encrypted" first to avoid false positives
            if (InStr(output, "not encrypted")) {
                WriteLog("Detected as NOT ENCRYPTED")
                WriteLog("--- CheckFileEncryption() completed - NOT ENCRYPTED ---")
                return "not_encrypted"
            } else if (InStr(output, "encrypted - ")) {
                WriteLog("Detected as ENCRYPTED")
                WriteLog("--- CheckFileEncryption() completed - ENCRYPTED ---")
                return "encrypted"
            } else {
                WriteLog("Could not parse output for encryption status")
                WriteLog("Searched for: 'not encrypted', 'encrypted - '")
                WriteLog("--- CheckFileEncryption() completed - PARSE ERROR ---")
            }
        } else {
            WriteLog("ERROR: Temp file was not created or could not be read")
            WriteLog("--- CheckFileEncryption() completed - FILE ERROR ---")
        }
        
        WriteLog("Returning error (end of function)")
        return "error"
        
    } catch as err {
        WriteLog("EXCEPTION caught in CheckFileEncryption:")
        WriteLog("Error Message: " . err.Message)
        WriteLog("Error Line: " . err.Line)
        WriteLog("Error File: " . err.File)
        WriteLog("--- CheckFileEncryption() completed - EXCEPTION ---")
        return "error"
    }
}

; Function to decrypt a file using FastPass
DecryptFile(filePath, password) {
    try {
        ; Change to FastPass directory
        fastPassDir := A_ScriptDir
        
        ; Use in-place decryption - let FastPass handle the output directly
        ; Capture output to verify success since exit codes are unreliable
        tempFile := A_Temp . "\fastpass_decrypt_" . A_TickCount . ".txt"
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python main.py decrypt -p "' . password . '" -i "' . filePath . '" > "' . tempFile . '" 2>&1"'
        
        ; Run the command
        result := RunWait(cmd, fastPassDir, "Hide")
        
        ; Check output for success/failure indicators
        if (FileExist(tempFile)) {
            output := FileRead(tempFile)
            
            ; Clean up temp file
            try {
                FileDelete(tempFile)
            } catch {
                ; Ignore cleanup errors
            }
            
            ; Check for success indicators in output
            if (InStr(output, "All operations successful") || InStr(output, "Successful: 1")) {
                return "success"
            }
        }
        
        return "error"
    } catch as err {
        return "error"
    }
}

; Function to encrypt a file using FastPass
EncryptFile(filePath, password) {
    try {
        ; Change to FastPass directory
        fastPassDir := A_ScriptDir
        
        ; Use in-place encryption - let FastPass handle the output directly  
        ; Capture output to verify success since exit codes are unreliable
        tempFile := A_Temp . "\fastpass_encrypt_" . A_TickCount . ".txt"
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python main.py encrypt -p "' . password . '" -i "' . filePath . '" > "' . tempFile . '" 2>&1"'
        
        ; Run the command
        result := RunWait(cmd, fastPassDir, "Hide")
        
        ; Check output for success/failure indicators
        if (FileExist(tempFile)) {
            output := FileRead(tempFile)
            
            ; Clean up temp file
            try {
                FileDelete(tempFile)
            } catch {
                ; Ignore cleanup errors
            }
            
            ; Check for success indicators in output
            if (InStr(output, "All operations successful") || InStr(output, "Successful: 1")) {
                return "success"
            }
        }
        
        return "error"
    } catch as err {
        return "error"
    }
}

; WriteLog function for debugging
WriteLog(message) {
    global logFile
    try {
        timestamp := FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")
        logEntry := timestamp . " | " . message . "`n"
        FileAppend(logEntry, logFile)
    } catch as err {
        ; If logging fails, show a message (but don't crash)
        MsgBox("Failed to write to log file: " . err.Message, "Log Error")
    }
}

; Function to check if file format is supported by FastPass
IsFileFormatSupported(filePath) {
    ; Extract file extension
    SplitPath(filePath, , , &ext)
    
    ; Convert to lowercase for comparison
    ext := StrLower(ext)
    
    ; List of supported formats from FastPass CLI help
    supportedFormats := [".pdf", ".docx", ".xlsx", ".pptx", ".potx", ".docm", ".xlsm", ".pptm", ".dotx", ".xltx"]
    
    ; Check if extension is in supported list
    for format in supportedFormats {
        if (ext == format) {
            return true
        }
    }
    
    return false
}

; Show startup message
WriteLog("Startup message displayed to user")
MsgBox("FastPass File Explorer Integration loaded successfully!`n`nHotkeys (active when File Explorer is focused):`n• Ctrl+Alt+D: Decrypt selected file`n• Ctrl+Alt+E: Encrypt selected file`n• Ctrl+Alt+H: Check encryption status`n`nDebug log: " . logFile, "FastPass - Ready")