# Universal Flowchart Specification Template

## Overview
This document defines the standardized template and specifications for creating detailed implementation flowcharts for any software project. This template provides a comprehensive framework for visualizing complex code-level implementation flows.

## Design Philosophy
- **Every code block represented**: Each flowchart element maps to specific code blocks that will be labeled in implementation
- **Complete detail retention**: No simplification or condensation that would lose implementation details
- **Visual clarity through color coding**: Consistent color scheme to differentiate element types
- **Error path visibility**: Clear visual indication of error handling flows

## HTML Template Structure

### Document Layout
```html
<!DOCTYPE html>
<html>
<head>
    <title>[Project Name] - Complete Code-Level Implementation Flowchart</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@11.6.0/dist/mermaid.min.js"></script>
    <!-- CSS styles -->
</head>
<body>
    <div class="container">
        <!-- Header section -->
        <!-- Legend section -->
        <!-- Controls section -->
        <!-- Diagram section -->
    </div>
    <!-- JavaScript section -->
</body>
</html>
```

### Required CSS Classes
```css
.container {
    background-color: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.legend {
    background-color: #f9f9f9;
    padding: 15px;
    border-radius: 5px;
    margin-bottom: 20px;
    border-left: 4px solid #f57c00;
}

.mermaid {
    background-color: white;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 20px;
    overflow: auto;
    text-align: center;
}
```

## Mermaid Configuration

### Required Settings
```javascript
mermaid.initialize({ 
    startOnLoad: false,  // Use dynamic loading
    theme: 'default',
    flowchart: {
        useMaxWidth: true,
        htmlLabels: false  // Prevents HTML parsing conflicts
    },
    securityLevel: 'loose',
    maxTextSize: 900000,  // Set to 900KB for large diagrams
    suppressErrorRendering: false,
    logLevel: 'error',
    deterministicIds: true,
    deterministicIDSeed: '[project-name]-flowchart',
    wrap: true,
    fontSize: 14,
    fontFamily: 'Arial, sans-serif',
    curve: 'basis'
});
```

### Dynamic Content Loading
```javascript
// Store Mermaid content as JavaScript template literal
const mermaidContent = `flowchart TD
    // Flowchart content here
`;

// Load content dynamically to avoid HTML parsing issues
const diagramElement = document.getElementById('diagram');
diagramElement.textContent = mermaidContent;
diagramElement.className = 'mermaid';

// Manual rendering after content load
setTimeout(() => {
    mermaid.init(undefined, document.getElementById('diagram'));
}, 100);
```

## Color Coding Standards

### Node Types and Colors

#### Business Logic (Orange)
- **Color**: `fill:#fff8e1,stroke:#f57c00,stroke-width:3px`
- **Usage**: Core application logic, data processing, main workflows, domain-specific operations
- **CSS Class**: `businessLogic`

#### Security Operations (Pink)
- **Color**: `fill:#fce4ec,stroke:#e91e63,stroke-width:2px`
- **Usage**: Input validation, access control, data sanitization, security checks
- **CSS Class**: `securityBox`

#### Standard Processing (Green)
- **Color**: `fill:#e8f5e8,stroke:#4caf50,stroke-width:2px`
- **Usage**: I/O operations, parsing, validation, cleanup, standard workflows
- **CSS Class**: `processBox`

#### Decision Points (Orange)
- **Color**: `fill:#fff3e0,stroke:#ff9800,stroke-width:2px`
- **Usage**: All branching logic, conditionals, routing decisions
- **CSS Class**: `decisionBox`

#### Error Conditions (Red)
- **Color**: `fill:#ffcdd2,stroke:#d32f2f,stroke-width:2px`
- **Usage**: Error states, failure conditions, exception handling
- **CSS Class**: `errorBox`

#### Success/Exit Points (Blue)
- **Color**: `fill:#e3f2fd,stroke:#2196f3,stroke-width:2px`
- **Usage**: Successful completion, help displays, normal exits
- **CSS Class**: `successBox`

### Error Path Edge Styling
- **Target**: All edges leading to error terminal nodes
- **Color**: `stroke:#d32f2f` (red)
- **Width**: `stroke-width:3px`
- **Implementation**: JavaScript function `styleErrorPaths()` applied after diagram rendering

#### CSS for Error Paths
```css
.mermaid .edgePath.error-path path {
    stroke: #d32f2f !important;
    stroke-width: 3px !important;
}
```

#### JavaScript Implementation
```javascript
function styleErrorPaths() {
    const errorNodes = [
        'A1hError', 'A2aError', 'B1eError', 'C1dError', 'D2fError', 'E3aError'
        /* ... all project-specific error node IDs ... */
    ];
    
    const svg = document.querySelector('#diagram svg');
    const edges = svg.querySelectorAll('.edgePath');
    
    edges.forEach(edge => {
        const edgeId = edge.id || '';
        errorNodes.forEach(errorNode => {
            if (edgeId.includes(errorNode)) {
                const path = edge.querySelector('path');
                if (path) {
                    path.style.stroke = '#d32f2f';
                    path.style.strokeWidth = '3px';
                }
            }
        });
    });
}
```

## Node Naming Convention

### Node ID Format
- **Pattern**: `[Section][Subsection][Step][Variant]`
- **Example**: `A1hCheck`, `B2bDanger`, `D3cOffice`
- **Sections**: A (Initialization), B (Validation), C (Setup), D (Processing), E (Cleanup)

### Node Content Format
```
[NodeID]: [Primary Action]\n[Technical Detail]\n[Implementation Note]
```

**Example**:
```
A1h["A1h: Process User Input\nValidate and parse incoming user requests\nHandle edge cases and error conditions"]
```

## Required Controls

### Standard Buttons
1. **🔍 Zoom In** - Increase diagram scale
2. **🔍 Zoom Out** - Decrease diagram scale  
3. **↻ Reset Zoom** - Return to original scale
4. **💾 Download SVG** - Export diagram as SVG
5. **🖨️ Print** - Print the flowchart
6. **🔄 Force Render** - Re-render with maximum settings

### Removed Experimental Features
- **Load Pre-rendered SVG** - Removed as experimental/debugging feature
- **Test Simple Diagram** - Removed as experimental/debugging feature

### Control Implementation
```javascript
function zoomIn() {
    currentZoom += 0.1;
    diagram.style.transform = `scale(${currentZoom})`;
    diagram.style.transformOrigin = 'top left';
}

// Ctrl+Scroll zoom support
diagram.addEventListener('wheel', function(e) {
    if (e.ctrlKey) {
        e.preventDefault();
        if (e.deltaY < 0) {
            zoomIn();
        } else {
            zoomOut();
        }
    }
});
```

## Legend Requirements

### Required Legend Content
```html
<div class="legend">
    <h3>🎯 Legend: Every Code Block Represented</h3>
    <ul>
        <li class="business-logic"><strong>Business Logic (Orange):</strong> Core application logic, data processing, main workflows</li>
        <li class="security">Security Operations (Pink): Input validation, access control, data sanitization</li>
        <li class="process">Standard Processing (Green): I/O operations, parsing, validation, cleanup</li>
        <li class="decision">Decision Points (Orange): All branching logic and conditionals</li>
    </ul>
    <p><strong>Note:</strong> Each box represents a specific code block that will be labeled in the final implementation.</p>
</div>
```

## Error Handling

### Enhanced Error Display
```javascript
mermaid.parseError = function(err, hash) {
    // Properly stringify error objects
    let errorDetails = err.message || JSON.stringify(err, Object.getOwnPropertyNames(err), 2);
    
    // Display formatted error with workarounds
    const diagramDiv = document.getElementById('diagram');
    diagramDiv.innerHTML = `
        <div style="padding: 20px; border: 2px solid #f44336; background: #ffebee;">
            <h3>WARNING: Mermaid Rendering Error</h3>
            <pre>${errorDetails}</pre>
            <p><strong>Workarounds:</strong></p>
            <ul>
                <li>Check browser console (F12) for detailed error messages</li>
                <li>Try the 'Force Render' button</li>
                <li>Verify Mermaid syntax validity</li>
            </ul>
        </div>
    `;
};
```

## Content Guidelines

### Section Organization
1. **Section A**: Application initialization and input processing
2. **Section B**: Data validation and security checks  
3. **Section C**: Core system setup and configuration
4. **Section D**: Main processing pipeline
5. **Section E**: Cleanup and result reporting

### Detail Level Requirements
- **Complete implementation mapping**: Every code block must have corresponding flowchart element
- **No simplification**: Maintain full detail even for large diagrams
- **Technical accuracy**: Include actual method calls, error conditions, and data flows
- **Implementation readiness**: Flowchart should serve as implementation blueprint

## File Organization

### Required Files
- `[project]_flowchart.html` - Main flowchart file
- `flowchart_specification.md` - This specification document
- `[project]_specification.md` - Source specification document (optional)

### Version Control
- Commit flowchart updates with specification changes
- Tag major flowchart revisions
- Maintain changelog for flowchart modifications

## Quality Assurance

### Validation Checklist
- [ ] All error paths have red edge styling
- [ ] Color coding follows specification
- [ ] Legend accurately describes all node types
- [ ] All controls function correctly
- [ ] Diagram renders without errors
- [ ] Maximum text size accommodates content
- [ ] No experimental/debugging features in production
- [ ] Browser automation testing completed with screenshot verification

### Testing Requirements
- Test in multiple browsers (Chrome, Firefox, Safari)
- Verify zoom functionality
- Validate SVG export
- Check print layout
- Test error handling display

### **CRITICAL: LLM Browser Automation Testing Protocol**

#### **Mandatory Testing Before Completion**
When an LLM is working on flowchart creation or modification, the following testing protocol is **REQUIRED** before reporting completion to the user:

1. **Browser Automation Setup**
   ```javascript
   const puppeteer = require('puppeteer');
   const browser = await puppeteer.launch({ headless: false }); // Use headless: false for debugging
   const page = await browser.newPage();
   await page.setViewport({ width: 1920, height: 1080 });
   ```

2. **Load and Validate Flowchart**
   ```javascript
   // Navigate to flowchart
   await page.goto(`file://${absolutePathToFlowchartHTML}`, { 
       waitUntil: 'networkidle0' 
   });
   
   // Wait for Mermaid rendering
   await page.waitForSelector('#diagram svg', { timeout: 10000 });
   ```

3. **Screenshot Verification**
   ```javascript
   // Take full-page screenshot for verification
   await page.screenshot({ 
       path: 'flowchart-test-verification.png', 
       fullPage: true 
   });
   ```

4. **Functional Testing**
   ```javascript
   // Test zoom controls
   await page.click('button:has-text("Zoom In")');
   await page.waitForTimeout(500);
   await page.click('button:has-text("Reset Zoom")');
   
   // Test download functionality
   await page.click('button:has-text("Download SVG")');
   ```

5. **Error Detection**
   ```javascript
   // Check for Mermaid rendering errors
   const errorMessages = await page.$$eval('.error, [class*="error"]', 
       els => els.map(el => el.textContent));
   
   if (errorMessages.length > 0) {
       throw new Error(`Flowchart errors detected: ${errorMessages.join(', ')}`);
   }
   ```

6. **Required Success Criteria**
   - [ ] Flowchart loads without errors
   - [ ] SVG diagram is visible and properly rendered
   - [ ] All controls (zoom, download, etc.) function correctly
   - [ ] Error paths display with red edges
   - [ ] No JavaScript errors in console
   - [ ] Screenshot shows complete, properly formatted flowchart

#### **LLM Reporting Requirements**
The LLM **MUST NOT** report flowchart work as complete until:
1. All browser automation tests pass
2. Screenshot verification confirms proper rendering
3. No errors are detected in browser console
4. All functional requirements are validated

#### **Failure Protocol**
If browser automation testing fails:
1. LLM must diagnose and fix the issues
2. Re-run the complete testing protocol
3. Only report completion after all tests pass
4. Include screenshot evidence of successful rendering in the response

## Implementation Notes

### Known Limitations
- Edge styling requires manual counting in complex diagrams
- Large diagrams may hit browser rendering limits
- HTML content in node labels requires careful escaping

### Best Practices
- Use JavaScript template literals for Mermaid content
- Implement dynamic content loading to avoid HTML parsing conflicts
- Provide comprehensive error handling and user guidance
- Maintain consistent naming conventions throughout diagram
- Document any custom modifications to this specification

## Template Usage

### For New Projects
1. Copy HTML template structure
2. Replace project name and title
3. Update Mermaid content with project-specific flow
4. Apply color coding according to node type guidelines
5. Test all functionality before deployment
6. Document any specification deviations

### Maintenance
- Review flowchart accuracy with each major code change
- Update color coding if new node types are needed
- Maintain consistency with this specification
- Update specification document for any template changes

---

**Version**: 2.0  
**Last Updated**: 2025-07-26  
**Based on**: Universal software project flowchart template  
**Author**: Claude Code Assistant  
**Template Type**: Generalized for any software project