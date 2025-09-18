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
from javax.swing import JOptionPane, JTextField, JPanel, JLabel, JCheckBox, JTextArea, JScrollPane, JButton, JFrame, JTabbedPane, BorderFactory, JFileChooser
from java.awt import GridLayout, BorderLayout, FlowLayout, Toolkit, Font, Dimension
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from javax.swing.filechooser import FileNameExtensionFilter

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
                self.showResultsDialog(patterns)
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
        
        # Export path with browse button
        path_panel = JPanel(BorderLayout())
        default_path = os.path.join(os.path.expanduser("~"), "frida_patterns.json")
        path_field = JTextField(default_path)
        browse_btn = JButton("Browse...")
        browse_btn.addActionListener(BrowseActionListener(path_field))
        
        path_panel.add(path_field, BorderLayout.CENTER)
        path_panel.add(browse_btn, BorderLayout.EAST)
        
        panel.add(JLabel("Export path:"))
        panel.add(path_panel)
        
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
    
    def showResultsDialog(self, patterns):
        """Show results in an interactive dialog with copy functionality"""
        frame = JFrame("Pattern Extractor Results")
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setSize(1000, 700)
        frame.setLocationRelativeTo(None)
        
        # Create tabbed pane
        tabbedPane = JTabbedPane()
        
        # Summary tab
        summary_panel = self.createSummaryTab(patterns)
        tabbedPane.addTab("Summary", summary_panel)
        
        # Individual pattern tabs
        for i, pattern in enumerate(patterns):
            pattern_panel = self.createPatternTab(pattern)
            tab_name = pattern['name'][:15] + "..." if len(pattern['name']) > 15 else pattern['name']
            tabbedPane.addTab(tab_name, pattern_panel)
        
        # Export controls
        export_panel = self.createExportPanel(patterns)
        
        # Main layout
        frame.setLayout(BorderLayout())
        frame.add(tabbedPane, BorderLayout.CENTER)
        frame.add(export_panel, BorderLayout.SOUTH)
        
        frame.setVisible(True)
    
    def createSummaryTab(self, patterns):
        """Create summary tab with all patterns overview"""
        panel = JPanel(BorderLayout())
        
        # Summary text
        summary_text = []
        summary_text.append("Pattern Extraction Summary")
        summary_text.append("=" * 50)
        summary_text.append("Program: {}".format(currentProgram.getName()))
        summary_text.append("Total patterns: {}".format(len(patterns)))
        summary_text.append("Architecture: {}".format(str(currentProgram.getLanguage().getProcessor())))
        summary_text.append("")
        
        for pattern in patterns:
            summary_text.append("Function: {}".format(pattern['name']))
            summary_text.append("Address: {}".format(pattern['address']))
            summary_text.append("Pattern: {}".format(pattern['pattern']))
            summary_text.append("Size: {} bytes".format(pattern['size']))
            summary_text.append("-" * 40)
        
        text_area = JTextArea("\n".join(summary_text))
        text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        text_area.setEditable(False)
        
        scroll_pane = JScrollPane(text_area)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Copy button
        copy_btn = JButton("Copy All Patterns")
        copy_btn.addActionListener(CopyActionListener(text_area))
        
        btn_panel = JPanel(FlowLayout())
        btn_panel.add(copy_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        
        # Quick export buttons (use default path from config)
        quick_panel = JPanel(FlowLayout())
        quick_panel.setBorder(BorderFactory.createTitledBorder("Quick Export (Default Path)"))
        
        quick_json_btn = JButton("Quick Export JSON")
        quick_json_btn.addActionListener(ExportActionListener(self, patterns, "json"))
        quick_panel.add(quick_json_btn)
        
        quick_frida_btn = JButton("Quick Export Frida")
        quick_frida_btn.addActionListener(ExportActionListener(self, patterns, "frida"))
        quick_panel.add(quick_frida_btn)
        
        # Add both panels to main panel
        main_panel = JPanel(BorderLayout())
        main_panel.add(panel, BorderLayout.CENTER)
        main_panel.add(quick_panel, BorderLayout.SOUTH)
        
        return main_panel
    
    def createPatternTab(self, pattern):
        """Create individual pattern tab"""
        panel = JPanel(BorderLayout())
        
        # Pattern details
        details = []
        details.append("Function: {}".format(pattern['name']))
        details.append("Address: {}".format(pattern['address']))
        details.append("Description: {}".format(pattern['description']))
        details.append("")
        details.append("Raw Hex Pattern:")
        details.append(pattern['pattern'])
        details.append("")
        details.append("Raw Pattern (no spaces):")
        details.append(pattern['raw_pattern'])
        details.append("")
        
        if 'smart_pattern' in pattern:
            details.append("Smart Pattern (with wildcards):")
            details.append(pattern['smart_pattern'])
            details.append("")
        
        details.append("Frida Hook Code:")
        details.append("hooker.addPattern('{}',".format(pattern['name'].replace(' ', '_')))
        details.append("    '{}',".format(pattern.get('smart_pattern', pattern['pattern'])))
        details.append("    {")
        details.append("        description: '{}',".format(pattern['description']))
        details.append("        onEnter: function(args, context) {")
        details.append("            console.log('[{}] Hooked!');".format(pattern['name']))
        details.append("            hooker.defaultOnEnter.call(this, args, context);")
        details.append("        }")
        details.append("    }")
        details.append(");")
        details.append("")
        
        # Symbol information
        if 'symbol_info' in pattern:
            details.append("Symbol Information:")
            details.append("  Namespace: {}".format(pattern['symbol_info']['namespace']))
            details.append("  External: {}".format(pattern['symbol_info']['is_external']))
            if pattern['symbol_info']['aliases']:
                details.append("  Aliases: {}".format(", ".join(pattern['symbol_info']['aliases'])))
        
        # XRef information
        if 'xrefs' in pattern and pattern['xrefs']['references_to_count'] > 0:
            details.append("")
            details.append("Cross References ({} total):".format(pattern['xrefs']['references_to_count']))
            for call_site in pattern['xrefs']['call_sites'][:5]:  # Show first 5
                details.append("  {} <- {}".format(call_site['address'], call_site['caller']))
        
        text_area = JTextArea("\n".join(details))
        text_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        text_area.setEditable(False)
        text_area.setCaretPosition(0)  # Scroll to top
        
        scroll_pane = JScrollPane(text_area)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Button panel
        btn_panel = JPanel(FlowLayout())
        
        # Copy pattern button
        copy_pattern_btn = JButton("Copy Pattern")
        copy_pattern_btn.addActionListener(CopyTextActionListener(pattern['pattern']))
        btn_panel.add(copy_pattern_btn)
        
        # Copy raw pattern button
        copy_raw_btn = JButton("Copy Raw")
        copy_raw_btn.addActionListener(CopyTextActionListener(pattern['raw_pattern']))
        btn_panel.add(copy_raw_btn)
        
        # Copy Frida code button
        frida_code = "hooker.addPattern('{}', '{}', {{ description: '{}' }});".format(
            pattern['name'].replace(' ', '_'),
            pattern.get('smart_pattern', pattern['pattern']),
            pattern['description']
        )
        copy_frida_btn = JButton("Copy Frida Code")
        copy_frida_btn.addActionListener(CopyTextActionListener(frida_code))
        btn_panel.add(copy_frida_btn)
        
        # Copy all details button
        copy_all_btn = JButton("Copy All Details")
        copy_all_btn.addActionListener(CopyActionListener(text_area))
        btn_panel.add(copy_all_btn)
        
        panel.add(btn_panel, BorderLayout.SOUTH)
        
        return panel
    
    def createExportPanel(self, patterns):
        """Create export control panel"""
        panel = JPanel(FlowLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Export Options"))
        
        # Export JSON button with file chooser
        json_btn = JButton("Export JSON")
        json_btn.addActionListener(ExportWithChooserActionListener(self, patterns, "json"))
        panel.add(json_btn)
        
        # Export Frida script button with file chooser
        frida_btn = JButton("Export Frida Script")
        frida_btn.addActionListener(ExportWithChooserActionListener(self, patterns, "frida"))
        panel.add(frida_btn)
        
        # Copy all patterns as text button
        copy_all_btn = JButton("Copy All as Text")
        all_patterns_text = "\n".join([
            "{}:{}".format(p['name'], p['pattern']) for p in patterns
        ])
        copy_all_btn.addActionListener(CopyTextActionListener(all_patterns_text))
        panel.add(copy_all_btn)
        
        return panel
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

# Action Listeners for GUI
class CopyActionListener(ActionListener):
    def __init__(self, text_component):
        self.text_component = text_component
    
    def actionPerformed(self, event):
        text = self.text_component.getText()
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        selection = StringSelection(text)
        clipboard.setContents(selection, None)
        print("Copied to clipboard: {} characters".format(len(text)))

class CopyTextActionListener(ActionListener):
    def __init__(self, text):
        self.text = text
    
    def actionPerformed(self, event):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        selection = StringSelection(self.text)
        clipboard.setContents(selection, None)
        print("Copied to clipboard: {}".format(self.text[:50] + "..." if len(self.text) > 50 else self.text))

class ExportActionListener(ActionListener):
    def __init__(self, extractor, patterns, format_type):
        self.extractor = extractor
        self.patterns = patterns
        self.format_type = format_type
    
    def actionPerformed(self, event):
        try:
            if self.format_type == "json":
                self.extractor.exportJSON(self.patterns)
                print("Exported JSON to: {}".format(self.extractor.export_path))
            elif self.format_type == "frida":
                self.extractor.exportFridaScript(self.patterns)
                js_path = self.extractor.export_path.replace('.json', '.js')
                print("Exported Frida script to: {}".format(js_path))
        except Exception as e:
            print("Export error: {}".format(str(e)))

# Browse button action listener
class BrowseActionListener(ActionListener):
    def __init__(self, text_field):
        self.text_field = text_field
    
    def actionPerformed(self, event):
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Select Export Location")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        
        # Set file filters
        json_filter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
        js_filter = FileNameExtensionFilter("JavaScript files (*.js)", ["js"])
        all_filter = FileNameExtensionFilter("All files", ["*"])
        
        file_chooser.addChoosableFileFilter(json_filter)
        file_chooser.addChoosableFileFilter(js_filter)
        file_chooser.addChoosableFileFilter(all_filter)
        file_chooser.setFileFilter(json_filter)
        
        # Set initial directory
        current_path = self.text_field.getText()
        if current_path and os.path.dirname(current_path):
            file_chooser.setCurrentDirectory(File(os.path.dirname(current_path)))
            if os.path.basename(current_path):
                file_chooser.setSelectedFile(File(current_path))
        
        result = file_chooser.showSaveDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            self.text_field.setText(selected_file.getAbsolutePath())

# Export with file chooser action listener
class ExportWithChooserActionListener(ActionListener):
    def __init__(self, extractor, patterns, format_type):
        self.extractor = extractor
        self.patterns = patterns
        self.format_type = format_type
    
    def actionPerformed(self, event):
        # Show file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Export Patterns - Choose Location")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        
        # Set appropriate filter and default name
        if self.format_type == "json":
            file_filter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
            default_name = "{}_patterns.json".format(currentProgram.getName().replace(" ", "_"))
        elif self.format_type == "frida":
            file_filter = FileNameExtensionFilter("JavaScript files (*.js)", ["js"])
            default_name = "{}_patterns.js".format(currentProgram.getName().replace(" ", "_"))
        else:
            file_filter = FileNameExtensionFilter("All files", ["*"])
            default_name = "patterns.txt"
        
        file_chooser.setFileFilter(file_filter)
        file_chooser.setSelectedFile(File(default_name))
        
        # Set initial directory to user's home or desktop
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        if os.path.exists(desktop_path):
            file_chooser.setCurrentDirectory(File(desktop_path))
        else:
            file_chooser.setCurrentDirectory(File(os.path.expanduser("~")))
        
        result = file_chooser.showSaveDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            export_path = selected_file.getAbsolutePath()
            
            # Ensure proper extension
            if self.format_type == "json" and not export_path.endswith('.json'):
                export_path += '.json'
            elif self.format_type == "frida" and not export_path.endswith('.js'):
                export_path += '.js'
            
            try:
                # Temporarily set the export path
                original_path = self.extractor.export_path
                self.extractor.export_path = export_path
                
                if self.format_type == "json":
                    self.extractor.exportJSON(self.patterns)
                    print("Exported JSON to: {}".format(export_path))
                    JOptionPane.showMessageDialog(None, 
                        "Successfully exported {} patterns to:\n{}".format(len(self.patterns), export_path),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE)
                elif self.format_type == "frida":
                    self.extractor.exportFridaScript(self.patterns)
                    # For Frida, also show JSON location
                    json_path = export_path.replace('.js', '.json')
                    print("Exported Frida script to: {}".format(export_path))
                    print("Exported JSON data to: {}".format(json_path))
                    JOptionPane.showMessageDialog(None, 
                        "Successfully exported {} patterns to:\nFrida Script: {}\nJSON Data: {}".format(
                            len(self.patterns), export_path, json_path),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE)
                
                # Restore original path
                self.extractor.export_path = original_path
                
            except Exception as e:
                print("Export error: {}".format(str(e)))
                JOptionPane.showMessageDialog(None, 
                    "Export failed: {}".format(str(e)),
                    "Export Error", JOptionPane.ERROR_MESSAGE)

# Create and run the script
extractor = PatternExtractor()
extractor.run()