from Crypto.Cipher import AES
import binascii
import random

def rotate_hex_string_right_one(hex_string):
    """
    Rotates a given hexadecimal string one position to the right.

    Args:
        hex_string (str): Hexadecimal string to be rotated.

    Returns:
        str: Rotated hexadecimal string.
    """
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length must be even.")

    last_byte = hex_string[-2:]  # Get the last two characters (byte) of the string
    remaining_bytes = hex_string[:-2]  # Get the rest of the string (all but the last byte)
    rotated_hex_string = last_byte + remaining_bytes  # Concatenate the last byte to the beginning

    return rotated_hex_string

def get_transaction_identifier(hex_string):
    return hex_string[0:8]

def get_rotated_RNDA(hex_string):
    return hex_string[8:40]
"""
key_hex = "00000000000000000000000000000000"

key = binascii.unhexlify(key_hex)

response_hex = "17 77 C4 6D 9B 6E A9 51 D2 50 DD F2 73 33 A5 7B C8 D7 38 C8 D0 2A 8A B4 B8 32 EE 07 D1 7A 19 97"

response_hex = response_hex.replace(" ", "")

# Konwertuj klucz i zaszyfrowaną wiadomość na postać binarną
response = binascii.unhexlify(response_hex)

# Inicjalizacja szyfrowania AES w trybie CBC
cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))

# Rozszyfrowanie wiadomości
response_plain = cipher.decrypt(response)

# Konwersja odszyfrowanego tekstu na format szesnastkowy
response_plain_hex = binascii.hexlify(response_plain).decode().upper()

print(response_plain_hex)

TI = response_plain_hex[0:8]

print(TI)

RndA_rotated = response_plain_hex[8:40]

print(RndA_rotated)

RndA = rotate_hex_string_right_one(RndA_rotated)

print("RndA: ",RndA)

"""