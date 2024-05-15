from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import binascii


def generate_sesion_key(key, RNDA, RNDB, option):
    """
    Generate a session key using AES-CMAC encryption.

    Parameters:
        key (bytes): The encryption key (16, 24, or 32 bytes) for AES-CMAC.
        RNDA (str): Hexadecimal string representing random value A.
        RNDB (str): Hexadecimal string representing random value B.
        option (int): Determines the header to use (1 or 2).

    Returns:
        str: The session key as a hexadecimal string.

    Raises:
        ValueError: If `option` is not 1 or 2, or if `key` length is invalid.
     """
    key = binascii.unhexlify(key)
    if option not in [1, 2]:
        raise ValueError("Option must be 1 or 2.")

    if len(key) not in [16, 24, 32]:
        raise ValueError("Key length must be 16, 24, or 32 bytes.")

    header = "A55A00010080" if option == 1 else "5AA500010080"

    SV_XOR = hex(int(RNDA[4:16], 16) ^ int(RNDB[0:12], 16))[2:].upper()
    SV = header + RNDA[:4] + SV_XOR + RNDB[12:32] + RNDA[16:32]
    SV = binascii.unhexlify(SV)

    cipher = CMAC.new(key, ciphermod=AES)
    cipher.update(SV)
    ses_key = cipher.hexdigest().upper()

    return ses_key

"""
RNDA = "3F2506494F3E920D78AC1F4F6CE9A65E"

RNDB = "5F8BB23F38A40AFEBAEAAC5DEFA44E66"
key = "00000000000000000000000000000000"
key = binascii.unhexlify(key)

SesAuthENCKey = generate_sesion_key(key, RNDA, RNDB, 1)

print(SesAuthENCKey)

SesAuthMACKey = generate_sesion_key(key, RNDA, RNDB, 2)

print(SesAuthMACKey)


"""