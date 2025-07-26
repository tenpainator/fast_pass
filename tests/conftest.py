"""
FastPass Test Configuration and Fixtures
PyTest configuration and shared fixtures
"""

import pytest
import tempfile
import shutil
from pathlib import Path
import subprocess
import os

@pytest.fixture(scope="session")
def test_data_dir():
    """Fixture providing test data directory"""
    return Path(__file__).parent / "fixtures"

@pytest.fixture(scope="session") 
def sample_files_dir(test_data_dir):
    """Fixture providing sample files directory"""
    return test_data_dir / "sample_files"

@pytest.fixture
def temp_work_dir():
    """Fixture providing temporary working directory for each test"""
    temp_dir = tempfile.mkdtemp(prefix="fastpass_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def fastpass_executable():
    """Fixture providing path to FastPass executable"""
    # Return the module path for running FastPass
    return ["uv", "run", "python", "-m", "src"]

@pytest.fixture
def simple_test_pdf(temp_work_dir):
    """Create a simple test PDF"""
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Test PDF Content) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000216 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
310
%%EOF"""
    
    test_pdf = temp_work_dir / "test.pdf"
    with open(test_pdf, 'w') as f:
        f.write(pdf_content)
    
    return test_pdf

@pytest.fixture
def password_list_file(temp_work_dir):
    """Fixture providing password list file"""
    password_file = temp_work_dir / "passwords.txt"
    passwords = [
        "password123",
        "secret456", 
        "complex&password!",
        "test with spaces"
    ]
    
    with open(password_file, 'w', encoding='utf-8') as f:
        for password in passwords:
            f.write(f"{password}\n")
    
    return password_file