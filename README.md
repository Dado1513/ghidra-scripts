# Personal Ghidra-Scripts

## Ghidra Pattern Extractor Plugin

**Extract hex patterns from Ghidra functions for Frida dynamic analysis and penetration testing**

A comprehensive Ghidra plugin that extracts binary patterns from selected functions and exports them in formats ready for use with Frida hooking frameworks. Designed specifically for security researchers, penetration testers, and reverse engineers working on mobile app security assessments.

### Features

#### 🎯 **Smart Pattern Extraction**
- Extract hex patterns from any selected functions in Ghidra
- Configurable byte extraction length (default: 20 bytes)
- Smart wildcard generation for addresses and immediate values
- Cross-reference analysis and symbol information

#### 🖥️ **Interactive GUI Interface**
- Tabbed results viewer with individual pattern analysis
- Real-time clipboard copy functionality
- Multiple export formats (JSON, Frida Script)
- File browser integration for export location selection

#### 📋 **Multiple Copy Options**
- **Copy Pattern**: Hex pattern with spaces (`a1 18 00 f0 21 ec 45 f9`)
- **Copy Raw**: Pattern without spaces (`a11800f021ec45f9`)
- **Copy Frida Code**: Ready-to-use Frida hook code
- **Copy All Details**: Complete pattern information with metadata

#### 📤 **Export Formats**
- **JSON**: Simple pattern data compatible with automation tools
- **Frida Script**: Complete JavaScript file with PatternHooker integration
- **Quick Export**: One-click export to configured default paths

### Installation

#### Requirements
- Ghidra 10.0+ (tested with 10.1+)
- Java 11+ (included with Ghidra)

#### Setup
1. Download the `ghidra_pattern_extractor.py` script
2. Place in your Ghidra scripts directory:
   ```
   <GHIDRA_INSTALL>/Ghidra/Features/Python/ghidra_scripts/
   ```
   Or use a custom script directory via Script Manager → Script Directories
3. Refresh the Script Manager in Ghidra
4. The plugin will appear under the "User" category

### Usage

#### Basic Workflow

1. **Open your target binary in Ghidra**
2. **Navigate to functions of interest** (authentication, crypto, etc.)
3. **Select one or more functions:**
   - Single function: Click on function in listing or decompiler
   - Multiple functions: Drag-select or Ctrl+click multiple functions
4. **Run the Pattern Extractor script** from Script Manager
5. **Configure extraction options** in the dialog
6. **View and copy results** from the interactive interface

#### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| **Bytes to extract** | Number of bytes to extract from function start | 20 |
| **Smart wildcards** | Replace addresses/immediates with `??` wildcards | Enabled |
| **Output format** | Export format preference | frida |
| **Export path** | Default file location for exports | ~/frida_patterns.json |

#### Smart Wildcards Feature

The plugin automatically analyzes instructions to identify:
- **Memory addresses** that vary between runs
- **Immediate values** that might change with updates
- **Function pointers** and branch targets

These are replaced with `??` wildcards to create more robust patterns:

```
Original:  a1 18 00 f0 21 ec 45 f9 70 0d 00 b0 10 5a 41 f9
Smart:     a1 18 00 f0 ?? ?? ?? ?? 70 0d 00 b0 ?? ?? ?? ??
```

### Penetration Testing Workflow

#### 1. **Target Analysis Phase**
```ghidra
// In Ghidra, identify critical functions:
- Authentication methods
- Crypto operations  
- Security checks
- License validation
```

#### 2. **Pattern Extraction**
- Select critical functions
- Run Pattern Extractor with smart wildcards enabled
- Review patterns in the interactive dialog
- Copy specific patterns or export all as JSON

#### 3. **Dynamic Analysis**
```bash
# Load patterns into Frida for runtime analysis
...
```

#### 4. **Results Analysis**
- Monitor hooked functions during app execution
- Analyze arguments and return values
- Identify security bypasses and vulnerabilities

### Advanced Features

#### Cross-Reference Analysis
Each extracted pattern includes:
- **Caller Information**: Functions that call the target
- **Call Sites**: Specific addresses of function calls
- **Reference Count**: Total number of references

#### Symbol Metadata
Pattern data includes comprehensive symbol information:
- Primary function name and aliases
- Namespace information
- External/internal classification
- Mangled vs demangled names

#### Batch Processing
Select multiple functions to extract patterns in batch:
- Process entire modules or namespaces
- Filter by function characteristics
- Export comprehensive pattern libraries

### Troubleshooting

#### Common Issues

**No patterns extracted:**
- Ensure functions are properly selected before running the script
- Check that the target address range contains valid instructions
- Verify byte extraction length is appropriate for the function

**Pattern matching fails in Frida:**
- Try enabling smart wildcards to handle address variations
- Reduce pattern length if too specific
- Check for ASLR or code signing modifications

**Export errors:**
- Verify write permissions to export directory
- Ensure adequate disk space for large exports
- Check file path length limitations on Windows

#### Debug Information

Enable verbose output by checking the Ghidra console:
```
Error extracting pattern from functionName: detailed error message
Copied to clipboard: pattern length and content preview
Exported JSON to: /path/to/export/file.json
```

### Tips for Effective Pattern Creation

#### 1. **Function Selection Strategy**
- Target security-critical functions first
- Focus on unique implementation details
- Avoid overly generic utility functions

#### 2. **Pattern Length Optimization**
- Start with 16-32 bytes for most functions
- Use shorter patterns (8-16 bytes) for generic hooks
- Extend to 64+ bytes for highly specific targets

#### 3. **Wildcard Usage**
- Enable smart wildcards for cross-version compatibility
- Manually review generated patterns for accuracy
- Test patterns against different app versions

### 4. **Performance Considerations**
- Limit pattern sets to ~20-50 active patterns
- Use specific patterns to reduce false positives
- Monitor hooking performance in production

### Integration
### Using with Hooky Pattern Loader
The generated JSON files work directly with the [hooky_pattern_loader.py](https://github.com/Dado1513/Hooky/blob/master/hooky_pattern_loader.py) and [modular-frida-hooking-patter.js](./frida-scripts/modular-frida-hooking-pattern.js):

```bash
# Use extracted patterns with Frida
python hooky_pattern_loader.py -j extracted_patterns.json -t com.target.app
python hooky_pattern_loader.py -p "name:f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa dc c2 1d 94" -t com.target.app
frida -Uf com.target.app -l modular-frida-hooking-pattern.js
```
