# Hash Validation (hashval)

### hashval is a simple R function that validates a HASH given as input in terms of type, and format

Supported types are: MD5, SHA1, SHA256, SHA384, SHA512

Supported formats are: Binary, Hexadecimal

The function hasval takes as input a hash (string) and outputs the following:

1. Prints the type and the format of the given Hash when it is valid.
2. Creates a list (hashval_hash) that containes the four following components:
   - valid: stores TRUE or FALSE depending on the validity of the given Hash
   - type: specifies the type of the given Hash Validated. The five options are md5, sha1, sha256, sha384, sha512
   - format: specifies the format of the given Hash. The two options are binary and hexadecimal
   - hash: stores the given hash
