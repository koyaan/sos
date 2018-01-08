# Simple Online Security

This is a mirror of http://members.linznet.at/auwe the original website
for the Simple Online Security project.

# Do not use ! For educational purposes only !

###  Even `1.2` which uses RC4 is now considered broken, `1.0` is trivial XOR encryption. So again: **Do not use this for real secret data!**

### Also code is riddled with bugs, update is waiting on the [Post-Quantum Cryptography standardization](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)
  
```
$ ./sos 

         Simple Online Security

Usage:
SOS [input-file] [output-file] [password] [-c]
    [input-file]  file you want to encrypt
    [output-file] name of the encrypted file
    [password]    key for encryption
    [-c]          exclude percentage counter
```

Decryption demo: password ABCDEFG [1.2/crypt.htm](1.2/crypt.htm) 
