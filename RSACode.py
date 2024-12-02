import random

ThreeBytesChunks = []
ciphertext = []
hex_stringArray = []
int_stringArray = []

intergerText = []
hexdecimaltext = []
plainIntegerText = []
hexWithoutX = []
bytesFromHex = []

def is_num_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

def gcd_compute(e, phiN):
    while phiN != 0:
        e, phiN = phiN, e % phiN
    return e

def GeneratePublicKey(phiN):
    #e = 1430428331
    e = random.randint(2, phiN - 1)
    while gcd_compute(e, phiN) != 1:
        e = random.randint(2, phiN - 1)
    return e

def GeneratePrivateKey(e, phiN):
    d = modulo_inv(e, phiN)
    return d

def modulo_inv(e, phiN):
    m0, x0, x1 = phiN, 0, 1
    while e > 1:
        q = e // phiN
        phiN, e = e % phiN, phiN
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def checkPandQinRange(num):
    return 30000 < num < 65535

def divideMessageIntoThreeBytesChunks(mes):
    chunks = [mes[i:i+3] for i in range(0, len(mes), 3)]  # Divide into chunks of three letters each
    return chunks

def stringToHexadecimalConversion(ThreeBytesChunks):
    for word in ThreeBytesChunks:
            word_hex = ''
            for char in word:
                    word_hex  += (hex(ord(char))[2:])  # Convert character to 
            hex_stringArray.append(word_hex)        
    return hex_stringArray

def hexadecimalToIntConversion(stringHex):
          integers =   [int(hex_string, 16) for hex_string in stringHex]
          return integers

def square_and_multiply(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def encrypt_integer_or_signed_text(plaintext_integer, e_or_d,N):
    ciphertext = []
    # Encryption with square and multiply 
    for integerText in plaintext_integer:
            ciphertext.append(square_and_multiply(integerText, e_or_d, N))
    return ciphertext

def decrypt_integer(ciphertext, d, N):
    result = 1
    while d > 0:
        if d % 2 == 1:
            result = (result * ciphertext) % N
        ciphertext = (ciphertext * ciphertext) % N
        d //= 2
    return result

def int_to_hexadecimal(number):
    hexadecimal = ""
    while number > 0:
        remainder = number % 16
        if remainder < 10:
            hex_digit = remainder
        else:
            hex_digit = remainder - 10 + ord('A')
        hexadecimal = str(hex_digit) + hexadecimal
        number //= 16
        print("hexadecimal loop :",hexadecimal)
    return "0x" + hexadecimal

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def concatenate_chunks(chunks):
    return ''.join(map(str, chunks))

def sign_message(message, private_key_d, modulus):
    # Convert the message (your name) to an integer
    message_int = int.from_bytes(message.encode(), 'big')
    # Compute the signature: signature = message^d mod N
    signature = square_and_multiply(message_int, private_key_d, modulus)
    return signature

def encryp_methodsZipped(message, e_or_d, N):
     ThreeBytesChunks = divideMessageIntoThreeBytesChunks(message)
     print("ThreeBytesChunks :", ThreeBytesChunks)
    
     hex_stringArray = stringToHexadecimalConversion(ThreeBytesChunks)
     #print("Hexadecimal string:", hex_stringArray)
     
     int_stringArray = hexadecimalToIntConversion(hex_stringArray)
     #print("Int String : ", int_stringArray)      

     ciphertext = encrypt_integer_or_signed_text(int_stringArray, e_or_d, N)
     print("Ciphertext or Signed Text: ", ciphertext)  
     return ciphertext       

def decryp_methodsZipped(cipherChunks,e_or_d,N):
    intergerText = [int(num) for num in cipherChunks.split(',')]
    for num in intergerText:
        plainIntegerText.append(decrypt_integer(num,e_or_d,N))
    #print("plainIntegerText : ", plainIntegerText)
    
    for num in plainIntegerText:
        hexdecimaltext.append(hex(num))
        #hexdecimaltext.append(int_to_hexadecimal(num))
    #print("hexdecimaltext : ", hexdecimaltext)

    prefix = "0x"
    for hexT in hexdecimaltext:
        hexWithoutX.append(remove_prefix(hexT,prefix))
    #print("hexWithoutX",hexWithoutX)    

    for hexString in hexWithoutX:
        bytesFromHex.append(bytes.fromhex(hexString))
    print("bytesFromHex : ", bytesFromHex)

    FinalString = ''.join([chunk.decode('utf-8') for chunk in bytesFromHex])
    print("bytesFromHex : ", FinalString)
    return FinalString9

while True:
    generate_params = input("Generate values for P and Q ? (Y/N): ").strip().upper()
    if generate_params == 'Y':
        #break
        p = int(input("Enter value of P: "))
        if not is_num_prime(p) or not checkPandQinRange(p):
            print("P is not a prime number or not within the range (30000, 65535).")
            continue
        q = int(input("Enter value of Q: "))
        if not is_num_prime(q) or not checkPandQinRange(q):
            print("Q is not a prime number or not within the range (30000, 65535).")
            continue

        N = p * q
        phiN = (p - 1) * (q - 1)
        
        e_gen = input("Press '1' to generate a random public key (e) | Press '2' for posting your own value of public key e\n").strip().upper()
        if e_gen == '1':
            e = GeneratePublicKey(phiN)
        else :
            e = input("Enter value of e : ")
            e = int(e)

        print("Public key (e):", e)
        d = GeneratePrivateKey(e, phiN)
        print("Private key (d):", d) 
        print("Public key (N):", N)
        print("phiN : ", phiN)
        exit
    else :
        choice = input("1. Encrypt Message\n2. Decrypt Message\n3. Sign Message\n4. Verify Partner's Message\nEnter your choice: ")
        #MessageEncryption
        if choice == '1':
            # e, N = map(int, input("Enter your partner's public key (e, N): ").split())
            print("Enter partner keys")
            e = int(input("Enter e\n"))
            N = int(input("Enter N\n"))
            message = input("Enter the message for encryption: \n")
            ThreeBytesChunks = []
            ciphertext = []
            encryp_methodsZipped(message,e,N)
            #print("ciphertext : ", ciphertext) 

        #MessageDecryption
        elif choice == '2':
            print("Enter your private keys\n")
            d = int(input("Enter d\n"))
            N = int(input("Enter N\n"))
            cipherChunks = input("Enter Cipher Texts for decryption : \n")
            finalstring = decryp_methodsZipped(cipherChunks,d,N)

        #SignedMessage    
        elif choice == '3':
            message = input("Enter your message for signed text : ")
            d = int(input("Enter d\n"))
            N = int(input("Enter N\n"))
            # sign = sign_message(selfName, d, N)
            sign = encryp_methodsZipped(message, d, N)
            print("Your message:", message)
            #print("Signature:", sign)

        #SignVerification
        elif choice == '4':
            messageForVerifcation = []
            messageForVerifcation = input("Enter Partner's Signature for verification\n")
            message = input("Enter the message\n")
            N = int(input("Enter Partner's N : \n"))
            e = int(input("Enter Partner's e : \n"))
            #sign = sign_message(selfName, e, N)
            messageForVerifcationConv = decryp_methodsZipped(messageForVerifcation, e, N)
            if message == messageForVerifcationConv:
                print("Hurrraayyyyy!!!!!  Verification successfull\n")
                print("Partner's Original message : ", message)
                print("Partner's Signature message : ", messageForVerifcationConv)    


        
