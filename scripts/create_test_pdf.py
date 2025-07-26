#!/usr/bin/env python3
"""
Create a simple test PDF file for FastPass testing
"""

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    import sys
    from pathlib import Path
    
    def create_test_pdf(output_path: str):
        """Create a simple test PDF"""
        c = canvas.Canvas(output_path, pagesize=letter)
        
        # Add some content
        c.drawString(100, 750, "FastPass Test Document")
        c.drawString(100, 720, "This is a test PDF for FastPass encryption/decryption testing.")
        c.drawString(100, 690, "Created for testing purposes only.")
        
        # Add a second page
        c.showPage()
        c.drawString(100, 750, "Page 2 of Test Document")
        c.drawString(100, 720, "Additional content for testing multi-page PDFs.")
        
        c.save()
        print(f"Test PDF created: {output_path}")
    
    if __name__ == "__main__":
        output_file = Path(__file__).parent.parent / "test_sample.pdf"
        create_test_pdf(str(output_file))
        
except ImportError:
    # Fallback: create a minimal PDF manually
    import sys
    from pathlib import Path
    
    def create_minimal_pdf(output_path: str):
        """Create minimal PDF without reportlab"""
        # Very basic PDF structure
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
(FastPass Test PDF) Tj
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
        
        with open(output_path, 'w') as f:
            f.write(pdf_content)
        print(f"Minimal test PDF created: {output_path}")
    
    if __name__ == "__main__":
        output_file = Path(__file__).parent.parent / "test_sample.pdf"
        create_minimal_pdf(str(output_file))