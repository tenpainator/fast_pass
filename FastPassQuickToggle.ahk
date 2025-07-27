; FastPass Quick Toggle - AutoHotkey v2 Script
; Ctrl+Alt+4 to quickly encrypt/decrypt selected files
; POC script for testing FastPass integration with Windows Explorer

; Hotkey: Ctrl+Alt+4
^!4::FastPassQuickToggle()

FastPassQuickToggle() {
    ; Get the currently selected file from Windows Explorer
    selectedFile := GetSelectedFile()
    
    if (selectedFile == "") {
        MsgBox("No file selected. Please select a file in Windows Explorer first.", "FastPass Quick Toggle", "Icon!")
        return
    }
    
    ; Check if the selected file is supported
    if (!IsSupportedFile(selectedFile)) {
        MsgBox("Unsupported file format. FastPass supports PDF, DOCX, XLSX, PPTX files.", "FastPass Quick Toggle", "Icon!")
        return
    }
    
    ; Check the current encryption status
    encryptionStatus := CheckEncryptionStatus(selectedFile)
    
    if (encryptionStatus == "error") {
        MsgBox("Error checking file encryption status. Please check the file and try again.", "FastPass Quick Toggle", "IconX")
        return
    }
    
    if (encryptionStatus == "encrypted") {
        HandleEncryptedFile(selectedFile)
    } else if (encryptionStatus == "unencrypted") {
        HandleUnencryptedFile(selectedFile)
    } else {
        MsgBox("Unable to determine file encryption status.", "FastPass Quick Toggle", "IconX")
    }
}

GetSelectedFile() {
    ; Get the selected file from Windows Explorer
    try {
        ; Create Shell.Application COM object
        shellApp := ComObject("Shell.Application")
        
        ; Try to get the selected file from the active Explorer window
        for window in shellApp.Windows {
            if (window.HWND == WinGetID("A")) {
                if (window.Document.SelectedItems.Count > 0) {
                    return window.Document.SelectedItems.Item(0).Path
                }
            }
        }
    } catch {
        ; Fallback: try to get from clipboard if user copied file path
    }
    return ""
}

IsSupportedFile(filePath) {
    ; Check if file extension is supported by FastPass
    SplitPath(filePath, , , &ext)
    supportedExts := ["pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt"]
    
    for ext_check in supportedExts {
        if (StrLower(ext) == ext_check) {
            return true
        }
    }
    return false
}

CheckEncryptionStatus(filePath) {
    ; Run FastPass check-password command to determine encryption status
    fastPassPath := "c:\Dev\fast_pass"
    
    ; Escape the file path for command line
    escapedPath := '"' . filePath . '"'
    
    ; Build the command
    cmd := 'cd "' . fastPassPath . '" && python -m src check-password -i ' . escapedPath
    
    ; Run the command and capture output
    try {
        result := RunCmd(cmd)
        
        ; Parse the output to determine encryption status
        if (InStr(result, "requires password") || InStr(result, "encrypted") || InStr(result, "password protected")) {
            return "encrypted"
        } else if (InStr(result, "no password required") || InStr(result, "not encrypted") || InStr(result, "unencrypted")) {
            return "unencrypted"
        } else {
            ; If unclear, assume unencrypted (safer default)
            return "unencrypted"
        }
    } catch {
        return "error"
    }
}

HandleEncryptedFile(filePath) {
    ; File is encrypted - ask for password to decrypt
    fileName := ""
    SplitPath(filePath, &fileName)
    
    password := InputBox("File '" . fileName . "' is encrypted.`n`nEnter password to decrypt:", "FastPass - Decrypt File", "Password")
    
    if (password.Result == "Cancel") {
        return
    }
    
    ; Attempt to decrypt with the provided password
    success := DecryptFile(filePath, password.Value)
    
    if (success) {
        MsgBox("File successfully decrypted!", "FastPass - Success", "Iconi")
    } else {
        ; Wrong password - ask again
        MsgBox("Incorrect password. Please try again.", "FastPass - Error", "IconX")
        HandleEncryptedFile(filePath)  ; Recursive call to ask again
    }
}

HandleUnencryptedFile(filePath) {
    ; File is unencrypted - ask for password to encrypt
    fileName := ""
    SplitPath(filePath, &fileName)
    
    password := InputBox("File '" . fileName . "' is not encrypted.`n`nEnter password to encrypt:", "FastPass - Encrypt File", "Password")
    
    if (password.Result == "Cancel") {
        return
    }
    
    if (password.Value == "") {
        MsgBox("Password cannot be empty. Please try again.", "FastPass - Error", "IconX")
        HandleUnencryptedFile(filePath)  ; Ask again
        return
    }
    
    ; Attempt to encrypt with the provided password
    success := EncryptFile(filePath, password.Value)
    
    if (success) {
        MsgBox("File successfully encrypted!", "FastPass - Success", "Iconi")
    } else {
        MsgBox("Failed to encrypt file. Please check the file and try again.", "FastPass - Error", "IconX")
    }
}

DecryptFile(filePath, password) {
    ; Run FastPass decrypt command
    fastPassPath := "c:\Dev\fast_pass"
    
    ; Escape paths and password for command line
    escapedPath := '"' . filePath . '"'
    escapedPassword := '"' . password . '"'
    
    ; Build the decrypt command
    cmd := 'cd "' . fastPassPath . '" && python -m src decrypt -i ' . escapedPath . ' -p ' . escapedPassword
    
    try {
        result := RunCmd(cmd)
        
        ; Check if decryption was successful
        if (InStr(result, "Successfully decrypted") || InStr(result, "Success")) {
            return true
        } else {
            return false
        }
    } catch {
        return false
    }
}

EncryptFile(filePath, password) {
    ; Run FastPass encrypt command
    fastPassPath := "c:\Dev\fast_pass"
    
    ; Escape paths and password for command line
    escapedPath := '"' . filePath . '"'
    escapedPassword := '"' . password . '"'
    
    ; Build the encrypt command
    cmd := 'cd "' . fastPassPath . '" && python -m src encrypt -i ' . escapedPath . ' -p ' . escapedPassword
    
    try {
        result := RunCmd(cmd)
        
        ; Check if encryption was successful
        if (InStr(result, "Successfully encrypted") || InStr(result, "Success")) {
            return true
        } else {
            return false
        }
    } catch {
        return false
    }
}

RunCmd(cmd) {
    ; Run command and return output
    shell := ComObject("WScript.Shell")
    exec := shell.Exec("cmd.exe /c " . cmd)
    
    ; Wait for command to complete and get output
    exec.StdIn.Close()
    output := exec.StdOut.ReadAll()
    
    ; Also get error output
    errorOutput := exec.StdErr.ReadAll()
    
    ; Combine both outputs
    result := output . errorOutput
    
    return result
}

; Show info message when script loads
MsgBox("FastPass Quick Toggle loaded!`n`nPress Ctrl+Alt+4 while a file is selected in Explorer to encrypt/decrypt it.`n`nSupported formats: PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT", "FastPass Quick Toggle", "Iconi")