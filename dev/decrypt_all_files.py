"""
Decrypt all encrypted files using raw tools
Uses msoffcrypto-tool for Office files (including legacy formats), PyPDF2 for PDF files
"""

import subprocess
import sys
from pathlib import Path
import PyPDF2

def decrypt_office_file(input_file, output_file, password):
    """Decrypt Office file using msoffcrypto-tool"""
    print(f"Decrypting {input_file.name} -> {output_file.name}")
    
    try:
        result = subprocess.run([
            "msoffcrypto-tool",
            str(input_file),
            str(output_file),
            "-p", password
        ], capture_output=True, text=True, check=True)
        
        print(f"  Successfully decrypted {input_file.name}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"  Error decrypting {input_file.name}:")
        print(f"    Return code: {e.returncode}")
        print(f"    Stdout: {e.stdout}")
        print(f"    Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"  msoffcrypto-tool not found. Please install it with: pip install msoffcrypto-tool")
        return False

def decrypt_pdf_file(input_file, output_file, password):
    """Decrypt PDF file using PyPDF2"""
    print(f"Decrypting {input_file.name} -> {output_file.name}")
    
    try:
        with open(input_file, "rb") as input_stream:
            reader = PyPDF2.PdfReader(input_stream)
            
            # Check if PDF is encrypted
            if not reader.is_encrypted:
                print(f"  Warning: {input_file.name} is not encrypted, copying as-is")
                # Just copy the file
                with open(output_file, "wb") as output_stream:
                    input_stream.seek(0)
                    output_stream.write(input_stream.read())
                return True
            
            # Decrypt with password
            if not reader.decrypt(password):
                print(f"  Error: Incorrect password for {input_file.name}")
                return False
            
            # Create writer and copy all pages
            writer = PyPDF2.PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            
            # Write decrypted PDF
            with open(output_file, "wb") as output_stream:
                writer.write(output_stream)
        
        print(f"  Successfully decrypted {input_file.name}")
        return True
        
    except Exception as e:
        print(f"  Error decrypting {input_file.name}: {e}")
        return False

def main():
    """Decrypt all encrypted files"""
    print("Decrypting all encrypted files using raw tools...\n")
    
    # Define paths
    encrypted_dir = Path("dev/encrypted")
    output_dir = encrypted_dir / "encrypted-to-decrypted"
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Define password for all encrypted files
    password = "test123"
    
    # Find all encrypted files (exclude the output directory)
    encrypted_files = [f for f in encrypted_dir.glob("sample.*") if f.is_file()]
    
    if not encrypted_files:
        print("No encrypted files found in dev/encrypted/")
        return
    
    print("=== Decrypting All File Types ===")
    print(f"Password: {password}")
    print(f"Source directory: {encrypted_dir}")
    print(f"Output directory: {output_dir}\n")
    
    success_count = 0
    total_count = len(encrypted_files)
    
    for encrypted_file in encrypted_files:
        output_file = output_dir / encrypted_file.name
        
        # Determine which decryption method to use based on file extension
        file_extension = encrypted_file.suffix.lower()
        
        if file_extension == ".pdf":
            success = decrypt_pdf_file(encrypted_file, output_file, password)
        elif file_extension in [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]:
            success = decrypt_office_file(encrypted_file, output_file, password)
        else:
            print(f"Skipping {encrypted_file.name} - unsupported file type")
            continue
        
        if success:
            success_count += 1
        
        print()  # Add blank line between files
    
    print(f"=== Decryption Summary ===")
    print(f"Successfully decrypted: {success_count}/{total_count} files")
    
    if success_count > 0:
        print(f"\nDecrypted files created in: {output_dir}")
        print("Decrypted files:")
        for file_path in output_dir.glob("sample.*"):
            if file_path.is_file():
                size_kb = file_path.stat().st_size / 1024
                print(f"  {file_path.name} ({size_kb:.1f} KB)")

if __name__ == "__main__":
    main()