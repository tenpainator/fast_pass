"""
FastPass Comprehensive Test Configuration and Fixtures
PyTest configuration and shared fixtures for all test categories
"""

import pytest
import tempfile
import shutil
from pathlib import Path
import subprocess
import json
import os
from typing import Dict, List, Any

# Test markers for categorizing tests
pytest.mark.unit = pytest.mark.mark("unit", "Unit tests")
pytest.mark.integration = pytest.mark.mark("integration", "Integration tests") 
pytest.mark.e2e = pytest.mark.mark("e2e", "End-to-end tests")
pytest.mark.security = pytest.mark.mark("security", "Security tests")
pytest.mark.performance = pytest.mark.mark("performance", "Performance tests")

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
        "test with spaces",
        "unicode_пароль",
        "symbols@#$%^&*()",
        "verylongpasswordthatexceedsnormallimits1234567890"
    ]
    
    with open(password_file, 'w', encoding='utf-8') as f:
        for password in passwords:
            f.write(f"{password}\n")
    
    return password_file


@pytest.fixture(scope="session")
def project_root():
    """Fixture providing project root directory"""
    return Path(__file__).parent.parent


@pytest.fixture
def sample_pdf_file(temp_work_dir, project_root):
    """Fixture providing a sample PDF file for testing"""
    source_pdf = project_root / "dev" / "pdf" / "test1_docx.pdf"
    if source_pdf.exists():
        test_pdf = temp_work_dir / "test_sample.pdf"
        shutil.copy2(source_pdf, test_pdf)
        return test_pdf
    else:
        # Use the simple test PDF if real one not available
        return simple_test_pdf(temp_work_dir)


@pytest.fixture
def multiple_test_files(temp_work_dir, sample_pdf_file):
    """Fixture providing multiple test files for batch testing"""
    files = []
    
    if sample_pdf_file:
        files.append(sample_pdf_file)
        
        # Create additional test files by copying the PDF
        for i in range(3):
            additional_file = temp_work_dir / f"test_file_{i}.pdf"
            shutil.copy2(sample_pdf_file, additional_file)
            files.append(additional_file)
    
    return files


@pytest.fixture
def unsupported_test_files(temp_work_dir):
    """Fixture providing unsupported file formats for testing rejection"""
    files = {}
    
    # Create .txt file
    txt_file = temp_work_dir / "test.txt"
    txt_file.write_text("This is a text file that should be rejected")
    files["txt"] = txt_file
    
    # Create .doc file (fake - just rename a txt file)
    doc_file = temp_work_dir / "test.doc"
    doc_file.write_text("Fake legacy doc file")
    files["doc"] = doc_file
    
    return files


@pytest.fixture
def encrypted_test_files(temp_work_dir, sample_pdf_file, fastpass_executable, project_root):
    """Fixture providing pre-encrypted test files with known passwords"""
    encrypted_files = {}
    
    if sample_pdf_file and sample_pdf_file.exists():
        # Encrypt the PDF with a known password
        encrypted_pdf = temp_work_dir / "encrypted_sample.pdf"
        shutil.copy2(sample_pdf_file, encrypted_pdf)
        
        # Encrypt using FastPass
        result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(encrypted_pdf),
                "-p", "test123"
            ],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode == 0:
            encrypted_files["pdf"] = {
                "file": encrypted_pdf,
                "password": "test123"
            }
    
    return encrypted_files




# Helper functions for test utilities
def run_fastpass_command(fastpass_executable: List[str], args: List[str], cwd: Path = None, input_data: str = None) -> subprocess.CompletedProcess:
    """Run FastPass command and return result"""
    cmd = fastpass_executable + args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd,
        input=input_data
    )