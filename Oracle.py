import requests
import unicodedata
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

LOCAL = False

TargetUrl = "http://chals.syssec.dk:14000/submitdata"

if LOCAL:
    lkey = os.urandom(16)
    aes = AES.new(lkey, AES.MODE_CBC)
    payload = b'0000000000000000flag(abcdefghijklmnopqrstuvwxyz)'
    localct = aes.encrypt(pad(payload,16))




# Here's the basic script i use when i need to back up data!
def upload_data(encrypted_bytes):
    if LOCAL:
        try:
            aes2 = AES.new(lkey,AES.MODE_CBC)
            pt = aes2.decrypt(encrypted_bytes)
            a = unpad(pt,16)
        
            return True
        except:
            return False

    encrypted_data = encrypted_bytes.hex()
    payload = {}
    payload["submitted_data"] = encrypted_data
    resp = requests.post(TargetUrl, data=payload)
    return resp.status_code == 200

if LOCAL:
    cipher = localct.hex()


# Generates the first 256 hexadecimals
first_256_hex_strings = [f'{i:02x}' for i in range(256)]

# XOR function
def xor(a,b):
    res = [int(x)^int(y) for x,y in zip(a[::-1],b[::-1]) ]
    return bytes(res[::-1])


def split_string_into_pairs(input_string):
    if len(input_string) % 2 != 0:
        raise ValueError("Input string length must be even.")
    
    pairs = [input_string[i:i+2] for i in range(0, len(input_string), 2)]
    return pairs

# Function that attacks a single byte in the cipgertext.
def attackByte(cipherText, targetIndex, paddingLevel, secondTry):
    firstElements = "".join(cipherText[:targetIndex])
    lastElements = "".join(cipherText[targetIndex-(len(cipherText)-1):])
    for i in range(256):
        guess = firstElements+first_256_hex_strings[i]+lastElements
        response = upload_data(bytes.fromhex(guess))
        if response and (str(cipherText[targetIndex]) != str(first_256_hex_strings[i]) or secondTry):
            print(f"Padding oracle attack successful at index:")
            print(targetIndex)
            plainText = (xor(xor(bytes.fromhex(first_256_hex_strings[paddingLevel]), bytes.fromhex(first_256_hex_strings[i])), bytes.fromhex(cipherText[targetIndex]))).hex()
            return plainText
    else :
        print("Edge case: Must be original byte in ciphertext that forces correct padding.")
        print("Thus the padding we are trying to force must be the plaintext")
        plainText = first_256_hex_strings[paddingLevel]
        return plainText


# Given a string of ciphertext, this function will perform the Padding Oracle Attack.
def oracleAttack(ct):
    cipherText = split_string_into_pairs(ct)
    lengthOfCT = len(cipherText)
    print(lengthOfCT)
    result = ""
    if(lengthOfCT % 16 != 0):
        print("Incorrect length of input.")
        print("Cipher text string must a multiple of 16.")
        return ""
    for j in range(int(lengthOfCT/16)-1):
        inputString = cipherText[:lengthOfCT-(j*16)]
        tempResult = ""
        if(j == lengthOfCT/16):
            inputString = "00"*16
        for i in range(16):
            index = lengthOfCT - (j+1)*16 - (i+1)
            print("Current index: " + str(index))
            plainText = attackByte(inputString, index, i+1, False)
            tempResult = plainText + tempResult
            result = plainText + result
            inputString = adjustInputString(cipherText[:lengthOfCT-(j*16)], tempResult, i+1)  
    decodedResult = hex_to_ascii(result)
    return decodedResult

# Function that adjust the input string, ensuring that the padding is correct.
def adjustInputString(inputString, tempResult, paddingPosition):
    firstElements = "".join(inputString[:-32])
    lastElements = "".join(inputString[-16:])
    paddingString = computePaddingString(paddingPosition)
    OGCipherText = inputString[-32:]
    OGCipherText = "".join(OGCipherText[:16])
    tempResult = "00"*(16-(int(len(tempResult)/2))) + tempResult
    return split_string_into_pairs(firstElements + (xor(bytes.fromhex(tempResult), xor(bytes.fromhex(paddingString), bytes.fromhex(OGCipherText)))).hex() + lastElements)

# Function generating a paddingstring used for adjusting the input string.
def computePaddingString(position):
    result=""
    for i in range(position):
        result = first_256_hex_strings[position+1] + result
    result = "00"*(16-(position)) + result
    return result

# Function that translates hex to text (using ASCII)
def hex_to_ascii(hex_string):
    # Convert hexadecimal string to bytes
    byte_data = bytes.fromhex(hex_string)

    # Decode the bytes to ASCII string
    ascii_string = byte_data.decode('ascii')

    return ascii_string

# CipherText that has been intercepted.
cipher = "5840e323ff120abdabda5a71bff05e2cef13b08b22568d3258d0fecd5dbed4a91304ba9dd795e4428a5a82a1871a1d67a0a53bf9eee0d74e63d9a901f556d8c1"
res = oracleAttack(cipher)
print(res)

