# RSA-Encryption-and-Decryption
This Python program implements a simplified version of RSA encryption, decryption, digital signing, and signature verification.
"""
Key Features and Functionalities of the RSA Encryption Program

1. Prime Number Generation and Validation
   - The user inputs two large prime numbers, P and Q, which are validated to be prime and within a range (30,000 to 65,535).
   - These primes are used to compute:
     - N = P × Q: The modulus.
     - φ(N) = (P - 1) × (Q - 1): The totient for key generation.

2. Public and Private Key Generation
   - The public key e is either randomly generated (ensuring gcd(e, φ(N)) = 1) or input by the user.
   - The private key d is computed using the modular multiplicative inverse of e modulo φ(N).

3. Encryption and Decryption
   - Messages are broken into 3-byte chunks and converted into integers for processing.
     - Encryption: Uses RSA's formula: Ciphertext = plaintext^e mod N.
     - Decryption: Reverses the encryption: Plaintext = ciphertext^d mod N.
   - The encryption and decryption process leverages the Square-and-Multiply method for efficient computation.

4. Digital Signature
   - Signing: The message is signed using the private key d to produce a digital signature: Signature = message^d mod N.
   - Verification: The signature is decrypted using the sender's public key e and matched against the original message to confirm authenticity.

5. Message Conversion Utilities
   - Messages are converted to hexadecimal and integers to facilitate encryption and decryption.
   - Utility functions handle conversions, such as:
     - String to hexadecimal.
     - Hexadecimal to integer.
     - Integer to hexadecimal.

6. Interactive User Interface
   - The program provides a menu for the user to:
     1. Generate keys.
     2. Encrypt a message.
     3. Decrypt a ciphertext.
     4. Sign a message.
     5. Verify a partner’s signature.

7. Error Handling
   - Checks are included to ensure valid prime inputs for P and Q, correct key range, and randomness of public keys.
"""
