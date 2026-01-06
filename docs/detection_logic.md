# Detecition Logic

## Reading NVD JSON
- CVE applies to an asset only when atleast one block from configuration evaluates to true not single CPE.
- We can't grab one CPE and based on vulnerable=True/False evaluate if CVE applies or not.
- Negate inverses the given condition in CPEMatch not the whole configuration node.
