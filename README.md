# Ghidra Scripts

## ghidra_pattern_extractor
1. Configuration Dialog:

Browse button next to export path field
File chooser with proper filters (JSON/JS)
Default path can be customized

2. Results Dialog Export Options:

Export JSON/Frida Buttons: Opens file chooser for custom location
Quick Export Buttons: Uses the default path from configuration
Copy Buttons: All existing clipboard functionality

3. File Chooser Features:

Smart Default Names: Uses program name (e.g., "MyApp_patterns.json")
Proper Filters: JSON files (.json), JavaScript files (.js)
Default Locations: Starts in Desktop or Home directory
Auto Extension: Automatically adds .json or .js if missing
Success/Error Dialogs: Clear feedback on export status

4. Export Workflow:
Method 1 - Configure Once, Export Multiple Times:

Run script → Configure default export path
View results → Use "Quick Export" buttons (uses configured path)

Method 2 - Choose Location Each Time:

Run script → Configure basic options
View results → Use "Export JSON/Frida" buttons (opens file chooser)

Method 3 - Copy to Clipboard:

Use any of the copy buttons for immediate use

5. Export Locations:

Desktop: Primary default location
Home Directory: Fallback if desktop not found
Custom: User can browse to any location
Project Directory: Can navigate to Ghidra project folder