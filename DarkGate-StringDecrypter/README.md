# DarkGate String Decrypter
## _IDA Python script for decoding DarkGate strings_

This IDA Python Script was written to assist in decrypting strings found in the DarkGate payload. The script leverages some [helper functions](https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c ) from OALabs for extracting information from registers and setting comments. The blog associated with this script can be found: https://www.aon.com/cyber-solutions/aon_cyber_labs/darkgate-keylogger-analysis-masterofnone/

## Instructions
To run the script, follow these steps: 

- Label the Custom Base64 decoding function as _"decode_custom_base64_wrap"_
- Modify the Base64 character set in the script to match sample you are analyzing
- Label the Decryption function as _"decrypt"_
- File -> Script File...
- Select the Python file

### Locating custom Base64 wrapper function and decrypt function
The _"decrypt"_ and  _"decode_custom_base64_wrap"_ functions can be found via looking the decryption of the strings. When decrypting the encrypted strings, the malware moves the address of the encrypted and encoded string into the EAX register before calling a function that uses the custom Base64 alphabet. This MOV and CALL can be seen at 0x469B1C and 0x469B2C below. 

The call to _"decrypt"_ is at 0x469B21 below. The call to _"decode_custom_base64_wrap"_ is at 0x469B31 below. 

![image](https://github.com/strozfriedberg/DarkGateTools/assets/123113960/0f90d659-0f02-4cd5-a8e5-ef8305efed5c)

## References

- https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c 
