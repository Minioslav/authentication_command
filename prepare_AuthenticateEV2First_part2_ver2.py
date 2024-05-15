from Crypto.Cipher import AES
import binascii
import random

def decrypt_aes_cbc(key_hex, ciphertext_hex):
    """
    Decrypts AES CBC encrypted ciphertext using the provided key.

    Args:
        key_hex (str): Hexadecimal representation of the AES encryption key.
        ciphertext_hex (str): Hexadecimal representation of the encrypted ciphertext.

    Returns:
        str: Decrypted plaintext in hexadecimal format.
    """
    ciphertext_hex = ciphertext_hex.replace(" ", "")
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    decrypted_plaintext = cipher.decrypt(ciphertext)
    return binascii.hexlify(decrypted_plaintext).decode().upper()

def rotate_hex_string_left_one(hex_string):
  """
   Rotates a hexadecimal string to the left by one byte.

    Parameters:
        hex_string (str): A string of hexadecimal characters representing data.

    Returns:
        str: A string of hexadecimal characters with the first byte moved to the end.

    Raises:
        ValueError: If the length of `hex_string` is not even.

  """
  if len(hex_string) % 2 != 0:
    raise ValueError("invalid lenth")

 
  first_byte = hex_string[:2]


  remaining_bytes = hex_string[2:]


  rotated_hex_string = remaining_bytes + first_byte

  return rotated_hex_string

def encrypt_aes_cbc(data_hex, key_hex):
    """
    Encrypts data using AES CBC encryption with the provided key.

    Args:
        data_hex (str): Hexadecimal representation of the data to be encrypted.
        key_hex (str): Hexadecimal representation of the AES encryption key.

    Returns:
        str: Encrypted ciphertext in hexadecimal format.
    """
    key = binascii.unhexlify(key_hex)
    data = binascii.unhexlify(data_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    encrypted_data = cipher.encrypt(data)
    return binascii.hexlify(encrypted_data).decode().upper()

def generate_command_hex(data_hex):
    """
    Generates a command string in hexadecimal format based on the provided data.

    Args:
        data_hex (str): Hexadecimal representation of the data.

    Returns:
        str: Command string in hexadecimal format.
    """
    cmd = "90AF000020" + data_hex + "00"
    return cmd

def generate_random_hex_string(length=16):
  """
  Generates a random hexadecimal string of the specified length.

    Parameters:
        length (int, optional): The length of the hexadecimal string in bytes (default is 16).

    Returns:
        str: A string of hexadecimal characters representing random data.

    Raises:
        ValueError: If the `length` is not positive.
  """
  if length <= 0:
    raise ValueError("Długość łańcucha heksadecymalnego musi być dodatnia.")


  hex_digits = "0123456789ABCDEF"


  random_bytes = [random.choice(hex_digits) for _ in range(length * 2)]


  random_hex_string = "".join(random_bytes)

  return random_hex_string 

"""
# Example usage
ciphertext_hex = "7C 07 1B 7B 6B 7F C2 AE D6 7F BE AC 77 D6 6C 30 "
expected_plaintext_hex = "B9E2FC789B64BF237CCCAA20EC7E6E48"
key_hex = "00000000000000000000000000000000"

# Decrypt the ciphertext
decrypted_plaintext_hex = decrypt_aes_cbc(key_hex, ciphertext_hex)

# Rotate the decrypted plaintext to the right by one position
rotated_hex_string = rotate_hex_string_left_one(decrypted_plaintext_hex)

# Generate random data
random_data_hex = generate_random_hex_string(length=16)

# Concatenate random data with rotated plaintext
concatenated_hex = random_data_hex + rotated_hex_string

# Encrypt the concatenated data
encrypted_data_hex = encrypt_aes_cbc(concatenated_hex, key_hex)

# Generate command based on the encrypted data
command_hex = generate_command_hex(encrypted_data_hex)

print("Decrypted plaintext:", decrypted_plaintext_hex)
print("Rotated plaintext:", rotated_hex_string)
print("Encrypted concatenated data:", encrypted_data_hex)
print("Random challenge: ", random_data_hex)
print("Command:", command_hex)
"""