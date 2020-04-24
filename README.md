# PEFile Service

This Assemblyline service runs the PEFile application against windows executables.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

This services attempts to extract PE headers and provides the following information in the result output (when available):

- Entry point address
- Linker Version
- OS Version
- Time Date Stamp (AL tag: file.pe.linker.timestamp)
- Machine Type
- RICH HEADER Info
- DATA DIRECTORY Info
- SECTIONS Info, including:
    - hash (AL tag: file.pe.sections.hash)
- DEBUG Info, including:
    - PDB Filename (AL tag: file.pe.pdb_filename)
- IMPORTs Info, including:
    - Table Listing
    - Import Hashes (AL tags: file.pe.imports.md5, file.pe.imports.sorted_sha1)
    - Fuzzy import hashes (tags: file.pe.imports.fuzzy, file.pe.imports.sorted_fuzzy)
- EXPORTs Info, including:
    - Module Name (AL tag: file.pe.exports.module_name)
- RESOURCES Info, including:
    - Name (AL tag: file.pe.resources.name)
    - Language (AL tag: file.pe.resources.language)
    - VersionInfo:
        - LangID
        - Original Filename (AL tag: file.pe.version.filename)
        - File Description (AL tag: file.pe.version.description)
- Authenticode Signature Information
    - Done using [signify](https://signify.readthedocs.io/en/latest/)
    - Extracted to AL tags cert.* (only the certificate information for the signing certificate)
- [API Vector](http://byte-atlas.blogspot.com/2018/04/apivectors.html) extraction

