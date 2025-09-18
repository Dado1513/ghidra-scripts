# Ghidra Pattern Extractor Plugin
# Extract hex patterns from selected functions for Frida hooking
# Place in ghidra_scripts directory

import json
import os
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SymbolType
from java.io import File, FileWriter
from javax.swing import JOptionPane, JTextField, JPanel, JLabel, JCheckBox
from java.awt import GridLayout

class PatternExtractor(GhidraScript):
    def __init__(self):
        super(PatternExtractor, self).__init__()
        self.default_bytes = 20
        self.output_format = "frida"
        self.include_wildcards = True
        self.export_path = ""
        
    def run(self):
        """Main execution method"""
        try:
            if not self.showOptionsDialog():
                return
                
            selected_functions = self.getSelectedFunctions()
            if not selected_functions:
                self.popup("No functions selected. Please select one or more functions.")
                return
                
            patterns = []
            for func in selected_functions:
                pattern_data = self.extractPattern(func)
                if pattern_data:
                    patterns.append(pattern_data)
                    
            if patterns:
                self.exportPatterns(patterns)
                self.popup("Exported {} patterns to {}".format(len(patterns), self.export_path))
            else:
                self.popup("No patterns extracted.")
                
        except Exception as e:
            self.popup("Error: {}".format(str(e)))
            
    def showOptionsDialog(self):
        """Show configuration dialog"""
        panel = JPanel(GridLayout(0, 2))
        
        # Bytes to extract
        bytes_field = JTextField(str(self.default_bytes))
        panel.add(JLabel("Bytes to extract:"))
        panel.add(bytes_field)
        
        # Include wildcards
        wildcards_check = JCheckBox("Smart wildcards", self.include_wildcards)
        panel.add(JLabel("Pattern options:"))
        panel.add(wildcards_check)
        
        # Output format
        format_field = JTextField(self.output_format)
        panel.add(JLabel("Output format:"))
        panel.add(format_field)
        
        # Export path
        default_path = os.path.join(os.path.expanduser("~"), "frida_patterns.json")
        path_field = JTextField(default_path)
        panel.add(JLabel("Export path:"))
        panel.add(path_field)
        
        result = JOptionPane.showConfirmDialog(
            None, panel, "Pattern Extractor Options", 
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
        )
        
        if result == JOptionPane.OK_OPTION:
            try:
                self.default_bytes = int(bytes_field.getText())
                self.include_wildcards = wildcards_check.isSelected()
                self.output_format = format_field.getText().lower()
                self.export_path = path_field.getText()
                return True
            except ValueError:
                self.popup("Invalid number of bytes specified.")
                return False
        return False
        
    def getSelectedFunctions(self):
        """Get currently selected functions"""
        functions = []
        
        # Try to get selected functions from listing
        selection = currentSelection
        if selection and not selection.isEmpty():
            function_manager = currentProgram.getFunctionManager()
            addresses = selection.getAddresses(True)
            
            for addr in addresses:
                func = function_manager.getFunctionContaining(addr)
                if func and func not in functions:
                    functions.append(func)
                    
        # If no selection, try current location
        if not functions:
            current_addr = currentAddress
            if current_addr:
                function_manager = currentProgram.getFunctionManager()
                func = function_manager.getFunctionContaining(current_addr)
                if func:
                    functions.append(func)
                    
        return functions
        
    def extractPattern(self, function):
        """Extract hex pattern from function"""
        try:
            entry_point = function.getEntryPoint()
            func_name = function.getName()
            
            # Get bytes from function start
            bytes_data = []
            addr = entry_point
            
            for i in range(self.default_bytes):
                try:
                    byte_val = getByte(addr)
                    bytes_data.append(byte_val & 0xFF)
                    addr = addr.add(1)
                except:
                    break
                    
            if not bytes_data:
                return None
                
            # Convert to hex pattern
            hex_pattern = self.createHexPattern(bytes_data, entry_point)
            
            # Get additional metadata
            symbol_info = self.getSymbolInfo(function)
            xrefs_info = self.getXRefsInfo(function)
            
            pattern_data = {
                "name": func_name,
                "address": str(entry_point),
                "pattern": hex_pattern,
                "raw_pattern": hex_pattern.replace(" ", ""),
                "frida_pattern": hex_pattern,
                "size": len(bytes_data),
                "symbol_info": symbol_info,
                "xrefs": xrefs_info,
                "description": "Pattern for {}".format(func_name),
                "metadata": {
                    "extracted_at": str(java.util.Date()),
                    "program": currentProgram.getName(),
                    "architecture": str(currentProgram.getLanguage().getProcessor()),
                    "bytes_extracted": len(bytes_data)
                }
            }
            
            # Apply smart wildcards if enabled
            if self.include_wildcards:
                pattern_data["smart_pattern"] = self.applySmartWildcards(hex_pattern, entry_point)
                
            return pattern_data
            
        except Exception as e:
            print("Error extracting pattern from {}: {}".format(function.getName(), str(e)))
            return None
            
    def createHexPattern(self, bytes_data, start_addr):
        """Convert bytes to hex pattern string"""
        hex_bytes = []
        for b in bytes_data:
            hex_bytes.append("{:02x}".format(b))
        return " ".join(hex_bytes)
        
    def applySmartWildcards(self, pattern, start_addr):
        """Apply intelligent wildcarding for addresses and constants"""
        bytes_array = pattern.split(" ")
        smart_pattern = []
        
        addr = start_addr
        for i, byte_hex in enumerate(bytes_array):
            try:
                # Check if this byte is part of an address/immediate value
                instruction = getInstructionAt(addr)
                if instruction:
                    # Get instruction operands
                    operands = instruction.getNumOperands()
                    is_address_byte = False
                    
                    for j in range(operands):
                        operand = instruction.getOpObjects(j)
                        for op in operand:
                            # Check if this is an immediate value or address
                            if hasattr(op, 'getAddress'):
                                is_address_byte = True
                                break
                                
                    # Wildcard immediate values and addresses
                    if is_address_byte and i > 0:  # Keep first few bytes for identification
                        smart_pattern.append("??")
                    else:
                        smart_pattern.append(byte_hex)
                else:
                    smart_pattern.append(byte_hex)
                    
                addr = addr.add(1)
            except:
                smart_pattern.append(byte_hex)
                
        return " ".join(smart_pattern)
        
    def getSymbolInfo(self, function):
        """Get symbol information for the function"""
        symbol_table = currentProgram.getSymbolTable()
        symbols = symbol_table.getSymbols(function.getEntryPoint())
        
        symbol_info = {
            "primary_name": function.getName(),
            "mangled_name": None,
            "namespace": str(function.getParentNamespace()),
            "symbol_type": "FUNCTION",
            "is_external": function.isExternal(),
            "aliases": []
        }
        
        for symbol in symbols:
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                if symbol.getName() != function.getName():
                    symbol_info["aliases"].append(symbol.getName())
                    
        return symbol_info
        
    def getXRefsInfo(self, function):
        """Get cross-reference information"""
        entry_point = function.getEntryPoint()
        xrefs_to = getReferencesTo(entry_point)
        
        xref_info = {
            "references_to_count": len(list(xrefs_to)),
            "callers": [],
            "call_sites": []
        }
        
        # Limit to first 10 references to avoid huge data
        for i, xref in enumerate(xrefs_to):
            if i >= 10:
                break
                
            from_addr = xref.getFromAddress()
            caller_func = getFunctionContaining(from_addr)
            
            call_site = {
                "address": str(from_addr),
                "caller": caller_func.getName() if caller_func else "unknown"
            }
            
            xref_info["call_sites"].append(call_site)
            
            if caller_func and caller_func.getName() not in xref_info["callers"]:
                xref_info["callers"].append(caller_func.getName())
                
        return xref_info
        
    def exportPatterns(self, patterns):
        """Export patterns to file"""
        try:
            if self.output_format == "frida":
                self.exportFridaScript(patterns)
            elif self.output_format == "json":
                self.exportJSON(patterns)
            else:
                self.exportJSON(patterns)  # Default to JSON
                
        except Exception as e:
            raise Exception("Export failed: {}".format(str(e)))
            
    def exportJSON(self, patterns):
        """Export as JSON"""
        export_data = {
            "metadata": {
                "extracted_from": currentProgram.getName(),
                "total_patterns": len(patterns),
                "extraction_options": {
                    "bytes_per_pattern": self.default_bytes,
                    "smart_wildcards": self.include_wildcards
                }
            },
            "patterns": patterns
        }
        
        with open(self.export_path, 'w') as f:
            json.dump(export_data, f, indent=2)
            
    def exportFridaScript(self, patterns):
        """Export as Frida script for native/iOS hooking"""
        script_lines = []
        script_lines.append("// Auto-generated Frida script from Ghidra")
        script_lines.append("// Pattern Extractor Plugin - Native/iOS Compatible")
        script_lines.append("// No Java.perform wrapper - works for iOS/native methods")
        script_lines.append("")
        script_lines.append("const hooker = new PatternHooker();")
        script_lines.append("")
        
        for pattern in patterns:
            pattern_name = pattern["name"].replace(" ", "_")
            hex_pattern = pattern.get("smart_pattern", pattern["pattern"])
            
            script_lines.append("// {}".format(pattern['description']))
            script_lines.append("// Original address: {}".format(pattern['address']))
            script_lines.append("hooker.addPattern('{}',".format(pattern_name))
            script_lines.append("    '{}',".format(hex_pattern))
            script_lines.append("    {")
            script_lines.append("        description: '{}',".format(pattern['description']))
            script_lines.append("        onEnter: function(args, context) {")
            script_lines.append("            console.log('[{}] Native method hooked!');".format(pattern_name))
            script_lines.append("            hooker.defaultOnEnter.call(this, args, context);")
            script_lines.append("        },")
            script_lines.append("        onLeave: function(retval, context) {")
            script_lines.append("            console.log('[{}] Return:', retval);".format(pattern_name))
            script_lines.append("        }")
            script_lines.append("    }")
            script_lines.append(");")
            script_lines.append("")
            
        script_lines.append("// Start pattern search for native methods")
        script_lines.append("setTimeout(() => {")
        script_lines.append("    console.log('Searching for native patterns...');")
        script_lines.append("    hooker.searchPatterns();")
        script_lines.append("}, 100);")
        script_lines.append("")
        script_lines.append("// Utility functions for iOS/native debugging")
        script_lines.append("globalThis.dumpModules = function() {")
        script_lines.append("    Process.enumerateModules().forEach(m => {")
        script_lines.append("        console.log(`${m.name}: ${m.base} - ${m.base.add(m.size)}`);")
        script_lines.append("    });")
        script_lines.append("};")
        script_lines.append("")
        script_lines.append("globalThis.findSymbol = function(name) {")
        script_lines.append("    const symbols = Process.enumerateSymbolsSync();")
        script_lines.append("    return symbols.filter(s => s.name && s.name.includes(name));")
        script_lines.append("};")
        
        # Write to .js file
        js_path = self.export_path.replace('.json', '.js')
        with open(js_path, 'w') as f:
            f.write('\n'.join(script_lines))
            
        # Also write JSON data
        self.exportJSON(patterns)

# Create and run the script
extractor = PatternExtractor()
extractor.run()