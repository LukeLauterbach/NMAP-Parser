# NMAP-Parser
Parses the output of NMAP and formats the results in an Excel file that can be easily copy/pasted into a penetration test report.

## Installation
1. Clone the repo
   ```sh
   git clone https://github.com/LukeLauterbach/NMAP-Parser.git
   ```
2. Install the sole dependency (if not already installed)
    ```sh
    pip install xlsxwriter
    ```

## Options
Option | Description
- | -
-f | NMAP output file to format
-o | Output filename
