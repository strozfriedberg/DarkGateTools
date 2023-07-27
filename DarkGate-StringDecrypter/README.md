# DarkGate String Decrypter
## _IDA Python script for decoding DarkGate strings_

This IDA Python Script was written to assist in decrypting strings found in the DarkGate payload. The script leverages some [helper functions](https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c ) from OALabs for extracing information from registers and setting comments. The blog associated with this script can be found: 

## Instructions
To run the script, follow these steps: 

- Label the Custom base64 deocding function as _"decode_custom_base64_wrap"_
- Label the Decryption function as _"decrypt"_
- File -> Script File...
- Select the python file

## References

- https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c 
