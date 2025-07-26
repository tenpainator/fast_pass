"""
FastPass Password Management System
Maps to: C3a-C5d Password Management and Testing from flowchart
"""

# A1a: Load System Tools
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging


class PasswordManager:
    """
    Password handling with multiple sources and priority algorithm
    Maps to: C3a-C5d from flowchart
    """
    
    def __init__(self, cli_passwords: List[str] = None, 
                 password_list_file: Optional[Path] = None,
                 stdin_mapping: Optional[Dict[str, str]] = None):
        """
        C3a-C3c: Initialize PasswordManager Class
        Set up password storage and management
        """
        
        # C3b: Remember User's Passwords
        self.cli_passwords = cli_passwords or []
        self.password_list_file = password_list_file
        self.stdin_mapping = stdin_mapping or {}
        
        # C3c: Prepare Password Storage
        self.password_list = []
        
        # C3d: Load Passwords from File
        if self.password_list_file:
            self._load_password_list()
    
    def _load_password_list(self) -> None:
        """
        C3d_Load: Read Passwords from File
        Load passwords from text file, one per line
        """
        try:
            with open(self.password_list_file, 'r', encoding='utf-8') as f:
                self.password_list = [line.strip() for line in f if line.strip()]
            
            # C3d_Load_Success: Passwords Successfully Loaded
            print(f"Loaded {len(self.password_list)} passwords from file")
            
        except FileNotFoundError:
            # C3d_Load_Error: Cannot Read Password File
            print(f"Warning: Password list file not found: {self.password_list_file}")
            self.password_list = []
        except Exception as e:
            print(f"Warning: Error reading password file {self.password_list_file}: {e}")
            self.password_list = []
    
    def get_password_candidates(self, file_path: Path) -> List[str]:
        """
        C4a-C4e: Get prioritized list of passwords to try for a file
        Build password list with priority ordering
        """
        
        # C4a: Start Building Password List
        candidates = []
        
        # Check for file-specific password from stdin mapping
        if self.stdin_mapping:
            file_name = file_path.name
            if file_name in self.stdin_mapping:
                candidates.append(self.stdin_mapping[file_name])
        
        # C4b: Add Command-Line Passwords First
        # Put passwords user typed in command first
        candidates.extend(self.cli_passwords)
        
        # C4c: Add File Passwords Second
        # Add passwords from password file after command-line ones
        candidates.extend(self.password_list)
        
        # C4d: Remove Duplicate Passwords
        # Eliminate passwords that appear multiple times
        seen = set()
        unique_candidates = []
        
        # C4d_Loop: Check Each Password for Duplicates
        for password in candidates:
            if password not in seen:
                # C4d_Add: Add New Password to List
                seen.add(password)
                unique_candidates.append(password)
        
        # C4e: Finalize Password List
        return unique_candidates
    
    def find_working_password(self, file_path: Path, crypto_handler) -> Optional[str]:
        """
        C5a-C5d: Find working password for file by trying all candidates
        Password testing mechanism
        """
        
        # C5a-C5b: Set Up Password Testing System and get passwords
        candidates = self.get_password_candidates(file_path)
        
        if not candidates:
            return None
        
        # C5c-C5d: Begin Trying Passwords
        for password in candidates:
            try:
                # C5d: Try Current Password
                if crypto_handler.test_password(file_path, password):
                    # C5d_Success: Found Working Password
                    return password
                    
            except Exception as e:
                # Continue trying other passwords
                continue
        
        # C5d_Failed: No Password Works
        return None
    
    def clear_passwords(self) -> None:
        """
        E3a-E3d: Clear passwords from memory for security
        Overwrite password memory
        """
        
        # E3a_Loop: Overwrite Password Memory
        if self.cli_passwords:
            for i in range(len(self.cli_passwords)):
                if self.cli_passwords[i]:
                    # E3a_Overwrite: Overwrite Password
                    self.cli_passwords[i] = 'X' * len(self.cli_passwords[i])
            self.cli_passwords.clear()
        
        if self.password_list:
            for i in range(len(self.password_list)):
                if self.password_list[i]:
                    self.password_list[i] = 'X' * len(self.password_list[i])
            self.password_list.clear()
        
        if self.stdin_mapping:
            for key in self.stdin_mapping:
                if self.stdin_mapping[key]:
                    self.stdin_mapping[key] = 'X' * len(self.stdin_mapping[key])
            self.stdin_mapping.clear()
        
        # E3c: Force Garbage Collection
        import gc
        gc.collect()