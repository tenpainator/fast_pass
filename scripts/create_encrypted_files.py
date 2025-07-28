"""
Create encrypted versions of generated sample files
Uses raw tools: msoffcrypto-tool for Office files, PyPDF2 for PDF files
"""

import subprocess
import sys
from pathlib import Path
import PyPDF2

def encrypt_office_file(input_file, output_file, password):
    """Encrypt Office file using msoffcrypto-tool"""
    print(f"Encrypting {input_file.name} -> {output_file.name}")
    
    try:
        result = subprocess.run([
            "msoffcrypto-tool",
            str(input_file),
            str(output_file),
            "-p", password,
            "-e"  # Enable encryption mode
        ], capture_output=True, text=True, check=True)
        
        print(f"  Successfully encrypted {input_file.name}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"  Error encrypting {input_file.name}:")
        print(f"    Return code: {e.returncode}")
        print(f"    Stdout: {e.stdout}")
        print(f"    Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"  msoffcrypto-tool not found. Please install it with: pip install msoffcrypto-tool")
        return False

def encrypt_pdf_file(input_file, output_file, password):
    """Encrypt PDF file using PyPDF2"""
    print(f"Encrypting {input_file.name} -> {output_file.name}")
    
    try:
        with open(input_file, "rb") as input_stream:
            reader = PyPDF2.PdfReader(input_stream)
            writer = PyPDF2.PdfWriter()
            
            # Copy all pages to writer
            for page in reader.pages:
                writer.add_page(page)
            
            # Encrypt with password
            writer.encrypt(
                user_password=password,
                owner_password=password,
                use_128bit=True
            )
            
            # Write encrypted PDF
            with open(output_file, "wb") as output_stream:
                writer.write(output_stream)
        
        print(f"  Successfully encrypted {input_file.name}")
        return True
        
    except Exception as e:
        print(f"  Error encrypting {input_file.name}: {e}")
        return False

def main():
    """Create encrypted versions of all supported files"""
    print("Creating encrypted versions of sample files...\n")
    
    # Define paths
    source_dir = Path("dev/file_generation")
    output_dir = Path("dev/encrypted")
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Define password for all encrypted files
    password = "test123"
    
    # Files to encrypt and their handlers
    files_to_encrypt = [
        # Modern Office formats (supported by msoffcrypto-tool)
        ("sample.docx", encrypt_office_file),
        ("sample.xlsx", encrypt_office_file), 
        ("sample.pptx", encrypt_office_file),
        
        # PDF format (supported by PyPDF2)
        ("sample.pdf", encrypt_pdf_file)
    ]
    
    success_count = 0
    total_count = len(files_to_encrypt)
    
    print("=== Encrypting Supported File Types ===")
    print(f"Password for all files: {password}\n")
    
    for filename, encrypt_func in files_to_encrypt:
        input_file = source_dir / filename
        output_file = output_dir / filename
        
        if not input_file.exists():
            print(f"  Source file not found: {input_file}")
            continue
            
        if encrypt_func(input_file, output_file, password):
            success_count += 1
    
    print(f"\n=== Encryption Summary ===")
    print(f"Successfully encrypted: {success_count}/{total_count} files")
    
    if success_count > 0:
        print(f"\nEncrypted files created in: {output_dir}")
        print("Files and their password:")
        for file_path in output_dir.glob("sample.*"):
            if file_path.is_file():
                size_kb = file_path.stat().st_size / 1024
                print(f"  {file_path.name} - Password: {password} ({size_kb:.1f} KB)")
    
    print(f"\nNote: Legacy formats (DOC, XLS, PPT) are not encrypted as they")
    print(f"cannot be encrypted with msoffcrypto-tool or our current toolchain.")

if __name__ == "__main__":
    main()