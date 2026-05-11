# Internal RST checker schemas

Bootstrap the official ICANN schema files into this folder:

`make bootstrap-internal-checker-schemas`

- `json/` for `.json` schema files
- `xml/` for `.xsd` schema files

The dashboard script inventories these files and includes them in the generated reports.
