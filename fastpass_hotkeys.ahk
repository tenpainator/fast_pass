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
        MsgBox("No file selected in File Explorer.", "FastPass - Error", "OK Icon!")
        return
    }
    
    ; Check if file is encrypted
    encryptionStatus := CheckFileEncryption(selectedFile)
    
    if (encryptionStatus == "error") {
        MsgBox("Error checking file encryption status.", "FastPass - Error", "OK Icon!")
        return
    }
    
    if (encryptionStatus == "not_encrypted") {
        MsgBox("File is not encrypted.", "FastPass - Info", "OK Info")
        return
    }
    
    if (encryptionStatus == "encrypted") {
        ; Prompt for password
        password := InputBox("Enter password to decrypt the file:", "FastPass - Decrypt", "Password").Text
        if (password == "") {
            MsgBox("Operation cancelled - no password provided.", "FastPass - Cancelled", "OK Info")
            return
        }
        
        ; Decrypt the file in-place
        result := DecryptFile(selectedFile, password)
        if (result == "success") {
            MsgBox("File decrypted successfully!", "FastPass - Success", "OK Icon64")
        } else {
            MsgBox("Failed to decrypt file. Please check the password and try again.", "FastPass - Error", "OK Icon!")
        }
    }
}

; Ctrl+Alt+E: Encrypt file (check if not encrypted, prompt for password, encrypt in-place)
^!e::
{
    selectedFile := GetSelectedFile()
    if (!selectedFile) {
        MsgBox("No file selected in File Explorer.", "FastPass - Error", "OK Icon!")
        return
    }
    
    ; Check if file is encrypted
    encryptionStatus := CheckFileEncryption(selectedFile)
    
    if (encryptionStatus == "error") {
        MsgBox("Error checking file encryption status.", "FastPass - Error", "OK Icon!")
        return
    }
    
    if (encryptionStatus == "encrypted") {
        MsgBox("File is already encrypted.", "FastPass - Info", "OK Info")
        return
    }
    
    if (encryptionStatus == "not_encrypted") {
        ; Prompt for password
        password := InputBox("Enter password to encrypt the file:", "FastPass - Encrypt", "Password").Text
        if (password == "") {
            MsgBox("Operation cancelled - no password provided.", "FastPass - Cancelled", "OK Info")
            return
        }
        
        ; Encrypt the file in-place
        result := EncryptFile(selectedFile, password)
        if (result == "success") {
            MsgBox("File encrypted successfully!", "FastPass - Success", "OK Icon64")
        } else {
            MsgBox("Failed to encrypt file. Please check the file format and try again.", "FastPass - Error", "OK Icon!")
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
        
        ; Build the command with correct FastPass CLI syntax (using -i flag)
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python -m src.app check -i "' . filePath . '""'
        WriteLog("Initial command: " . cmd)
        
        ; Capture the output by redirecting to temp file with enhanced error capture
        tempFile := A_Temp . "\fastpass_check_" . A_TickCount . ".txt"
        
        ; Try a different approach - capture both stdout and stderr, and also test if Python can import the module
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && echo Testing Python import... && python -c "import src.app; print(`'Import successful`')" && echo Running check command... && python -m src.app check -i "' . filePath . '" && echo Command completed." > "' . tempFile . '" 2>&1'
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
            
            if (InStr(output, "encrypted - ") || InStr(output, "encrypted.")) {
                WriteLog("Detected as ENCRYPTED")
                WriteLog("--- CheckFileEncryption() completed - ENCRYPTED ---")
                return "encrypted"
            } else if (InStr(output, "not encrypted") || InStr(output, "Status for")) {
                WriteLog("Detected as NOT ENCRYPTED")
                WriteLog("--- CheckFileEncryption() completed - NOT ENCRYPTED ---")
                return "not_encrypted"
            } else {
                WriteLog("Could not parse output for encryption status")
                WriteLog("Searched for: 'encrypted - ', 'encrypted.', 'not encrypted', 'Status for'")
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
        
        ; Create output filename (remove .encrypted extension or add .decrypted)
        outputPath := filePath
        if (SubStr(filePath, -10) == ".encrypted") {
            outputPath := SubStr(filePath, 1, -11)  ; Remove .encrypted
        } else {
            ; Add .decrypted before the file extension
            SplitPath(filePath, &name, &dir, &ext, &nameNoExt)
            outputPath := dir . "\" . nameNoExt . ".decrypted." . ext
        }
        
        ; Build the command with password
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python -m src.app decrypt -p "' . password . '" "' . filePath . '" "' . outputPath . '""'
        
        ; Run the command
        result := RunWait(cmd, fastPassDir, "Hide")
        
        ; Check if decryption was successful (return code 0)
        if (result == 0 && FileExist(outputPath)) {
            ; For in-place decryption, replace the original file
            if (outputPath != filePath) {
                FileMove(outputPath, filePath, true)
            }
            return "success"
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
        
        ; Create output filename
        SplitPath(filePath, &name, &dir, &ext, &nameNoExt)
        outputPath := dir . "\" . nameNoExt . ".encrypted." . ext
        
        ; Build the command with password
        cmd := 'cmd /c "cd /d "' . fastPassDir . '" && python -m src.app encrypt -p "' . password . '" "' . filePath . '" "' . outputPath . '""'
        
        ; Run the command
        result := RunWait(cmd, fastPassDir, "Hide")
        
        ; Check if encryption was successful (return code 0)
        if (result == 0 && FileExist(outputPath)) {
            ; For in-place encryption, replace the original file
            FileMove(outputPath, filePath, true)
            return "success"
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

; Show startup message
WriteLog("Startup message displayed to user")
MsgBox("FastPass File Explorer Integration loaded successfully!`n`nHotkeys (active when File Explorer is focused):`n• Ctrl+Alt+D: Decrypt selected file`n• Ctrl+Alt+E: Encrypt selected file`n• Ctrl+Alt+H: Check encryption status`n`nDebug log: " . logFile, "FastPass - Ready")