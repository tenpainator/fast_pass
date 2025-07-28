"""
FastPass Password Management System
"""

# A1a: Load System Tools
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging


class PasswordManager:
    """
    Password handling with multiple sources and priority algorithm
    """
    
    def __init__(self, cli_passwords: List[str] = None):
        """
        Set up password storage and management
        """
        
        # C3b: Remember User's Passwords
        self.cli_passwords = cli_passwords or []
        
        # C3c: Prepare Password Storage
        self.password_list = []
        self.stdin_mapping = {}
    
    def get_password_candidates(self, file_path: Path) -> List[str]:
        """
        Build password list with priority ordering
        """
        
        # C4a: Start Building Password List
        candidates = []
        
        # C4b: Add Command-Line Passwords (includes any from stdin)
        # Put passwords user typed in command (and any loaded from stdin)
        candidates.extend(self.cli_passwords)
        
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