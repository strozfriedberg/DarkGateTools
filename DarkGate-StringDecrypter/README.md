# DarkGate String Decrypter
## _IDA Python script for decoding DarkGate strings_

This IDA Python Script was written to assist in decrypting strings found in the DarkGate payload. The script leverages some [helper functions](https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c ) from OALabs for extracing information from registers and setting comments. The blog associated with this script can be found: 

## Instructions
To run the script, follow these steps: 

- Label the Custom base64 deocding function as _"decode_custom_base64_wrap"_
- Modify the Base64 character set in the script to match sample you are analyzing
- Label the Decryption function as _"decrypt"_
- File -> Script File...
- Select the python file

### Locating custom base64 wrapper function and decyrpt function
The _"decrypt"_ and  _"decode_custom_base64_wrap"_ functions can be found via looking the decryption of the strings. When decrypting the encrypted strings, the malware moves the address of the encrypted and encoded string into the EAX register before calling a function that uses the custom Base64 alphabet. This MOV and CALL can be seen at 0x469B1C and 0x469B2C below. 

![image](https://github.com/strozfriedberg/DarkGateTools/assets/123113960/dddb25e4-6c0d-46ba-b2de-f343a07fd56e)


## References

- https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c 
