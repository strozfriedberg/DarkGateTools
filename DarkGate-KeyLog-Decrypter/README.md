# DarkGate Keylog Decrypter
## _Delphi program for decrypting DarkGate keylog files_

This Delphi program utilizes the DCPCrypt Library to implement the AES CFB8bit encryption mode used by the DarkGate Keylogger. It is hardcoded with the AES key `masteroflog`. 

The program searches the current directory for any file ending in `.log`. If found, the program attempts to utilize the DecryptString method implemented by the DCPCrypt library. The cipher is initiated with a SHA1 hash of the key `masteroflog`. The DecryptString method implements the encryption using CFB8Bit Mode. 

## Compilation
To compile the script: 

- Download and install Lazarus
- Download and install the DCPCrypt library
- Open the file in Lazarus and compile using default paramters

## Initial Alpha Release
https://github.com/strozfriedberg/DarkGateTools/releases/tag/0.1.0-alpha
