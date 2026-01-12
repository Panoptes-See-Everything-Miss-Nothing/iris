# Detecition Logic

## Reading NVD JSON
- Configuration contains main detection logic information
- If operator is NOT present at configuration level, then default OR operator is considered
- In case of AND operator will be mentioned explicitly
- Each node has operator inside it which should be used to evaluate the result of each node using each CpeMatch, again if no operator is mentioned it will default to OR.
- Once the result of nodes is obtained, operator from configuration level is the used against obtained result of nodes
- Evaluated result will be the final result for the CVE.
