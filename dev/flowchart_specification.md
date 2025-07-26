# FastPass Flowchart Specification

## Overview
This document defines the standardized template and specifications for creating detailed implementation flowcharts for software projects, based on the FastPass Complete Code-Level Implementation Flowchart.

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
- **Usage**: Password handling, crypto operations, temp files, core business functions
- **CSS Class**: `businessLogic`

#### Security Operations (Pink)
- **Color**: `fill:#fce4ec,stroke:#e91e63,stroke-width:2px`
- **Usage**: Path validation, access control, sanitization, security checks
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
        'A1hError', 'A2aError', 'A2aBothError', /* ... all error node IDs ... */
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
- **Sections**: A (CLI/Init), B (Security/Validation), C (Crypto Setup), D (Processing), E (Cleanup)

### Node Content Format
```
[NodeID]: [Primary Action]\n[Technical Detail]\n[Implementation Note]
```

**Example**:
```
A1h["A1h: Read User's Commands\nProcess the command-line instructions user provided\nHandle cases where user asks for help or makes errors"]
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
        <li class="business-logic"><strong>Business Logic (Orange):</strong> [Description]</li>
        <li class="security">Security Operations (Pink): [Description]</li>
        <li class="process">Standard Processing (Green): [Description]</li>
        <li class="decision">Decision Points (Orange): [Description]</li>
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
1. **Section A**: CLI parsing and argument validation
2. **Section B**: Security validation and file format checking  
3. **Section C**: Crypto tool setup and password management
4. **Section D**: File processing pipeline
5. **Section E**: Cleanup and reporting

### Detail Level Requirements
- **Complete implementation mapping**: Every code block must have corresponding flowchart element
- **No simplification**: Maintain full detail even for large diagrams
- **Technical accuracy**: Include actual method calls, error conditions, and data flows
- **Implementation readiness**: Flowchart should serve as implementation blueprint

## File Organization

### Required Files
- `[project]_flowchart.html` - Main flowchart file
- `flowchart_specification.md` - This specification document
- `[project]_specification.md` - Source specification document

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

### Testing Requirements
- Test in multiple browsers (Chrome, Firefox, Safari)
- Verify zoom functionality
- Validate SVG export
- Check print layout
- Test error handling display

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

**Version**: 1.0  
**Last Updated**: 2025-07-26  
**Based on**: FastPass Complete Code-Level Implementation Flowchart  
**Author**: Claude Code Assistant