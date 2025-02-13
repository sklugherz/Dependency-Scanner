# Dependency-Scanner
Checks for vulnerabilities in dependencies based on the National Vulnerability Database (NVD)
This product uses data from the NVD API but is not endorsed or certified by the NVD.
Uses public api 


Initial version supports only python dependencies via requirements.txt file. 

Support for different platforms to be added: npm, etc.


Supply Chain Dependency Scanner


Create a tool that analyzes software dependencies for vulnerabilities
Integrate with package managers (npm, pip, etc.)
Alert on known CVEs and outdated packages
Real problem solved: Helps prevent supply chain attacks through vulnerable dependencies

Key Security Features:

Checks against National Vulnerability Database (NVD)
Version range analysis for vulnerabilities
Support for multiple package ecosystems (npm, PyPI)
Detailed vulnerability reporting

Software Engineering Best Practices:

Modular, object-oriented design
Error handling and input validation
Clear documentation and code organization
HTML report generation for findings

Real-World Applications:

Helps prevent supply chain attacks
Identifies outdated or vulnerable dependencies
Generates actionable security reports
Integrates with common development workflows

To extend this project further, you could:

Add More Package Ecosystems:

Maven for Java
Cargo for Rust
Composer for PHP

Enhance Security Features:

Add license compliance checking
Implement SBOMs generation
Add known malware checking
Include dependency tree analysis

Improve Reporting:

Add severity scoring
Create executive summaries
Generate PDF reports
Add remediation suggestions



## TODO

### add support for more package handlers

Maven for Java
Cargo for Rust
Composer for PHP


### add argument flags

    specify file format
    -f, --file=requirements.txt

    specify outfile and change output on outfile type, csv, pdf, html, cmdline
    -o, --outfile=outfile 

    print dependency tree to cmdline
    -t, --tree
