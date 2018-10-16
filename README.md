# PEFile Service

This Assemblyline service runs the PEFile application against windows executables.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

This services attempts to extract PE headers and provides the following information in the result output (when available):

- Entry point address
- Linker Version
- OS Version
- Time Date Stamp (AL tag: PE_LINK_TIME_STAMP)
- Machine Type
- RICH HEADER Info
- DATA DIRECTORY Info
- SECTIONS Info, including:
    - hash (AL tag: PE_SECTION_HASH)
- DEBUG Info, including:
    - PDB Filename (AL tag: PE_PDB_FILENAME)
- IMPORTs Info, including:
    - Table Listing
    - Import Hashes (AL tags: PE_IMPORT_MD5, PE_IMPORT_SORTED_SHA1)
    - Fuzzy import hashes (tags: PE_IMPORT_FUZZY, PE_IMPORT_FUZZY_SORTED)
- EXPORTs Info, including:
    - Module Name (AL tag: PE_EXPORT_MODULE_NAME)
- RESOURCES Info, including:
    - Name (AL tag: PE_RESOURCE_NAME)
    - Language (AL tag: PE_RESOURCE_LANGUAGE)
    - VersionInfo:
        - LangID
        - Original Filename (AL tag: PE_VERSION_INFO_ORIGINAL_FILENAME)
        - File Description (AL tag: PE_VERSION_INFO_FILE_DESCRIPTION)
- Authenticode Signature Information
    - done using a [branch](https://github.com/jdval/signify) of [signify](https://signify.readthedocs.io/en/latest/) that works with python2
    - Extracted to AL tags CERT_* (only the certificate information for the signing certificate)
- [API Vector](http://byte-atlas.blogspot.com/2018/04/apivectors.html) extraction

