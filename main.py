from prepare_AuthenticateEV2First_part2_ver2 import *
from interpret_response import *
from sesion_key_generation import *

key_hex = "00000000000000000000000000000000"

first_response_hex = input("Enter first response: ")
decrypted_RNDB = decrypt_aes_cbc(key_hex, first_response_hex)

rotated_hex_string = rotate_hex_string_left_one(decrypted_RNDB)

generated_RNDA = generate_random_hex_string(length=16)

concatenated_hex = generated_RNDA + rotated_hex_string

encrypted_data_hex = encrypt_aes_cbc(concatenated_hex, key_hex)

command_hex = generate_command_hex(encrypted_data_hex)

print("command: ", command_hex)

second_response_hex = input("Enter second response: ")

decrypted_second_response = decrypt_aes_cbc(key_hex, second_response_hex)

TI = get_transaction_identifier(decrypted_second_response)

print("trasaction identifier: ", TI)

rotated_RNDA = get_rotated_RNDA(decrypted_second_response)

received_RNDA = rotate_hex_string_right_one(rotated_RNDA)

if received_RNDA==generated_RNDA:
    print("successfully authenticated")

SesAuthENCKey = generate_sesion_key(key_hex, received_RNDA, decrypted_RNDB, 1)

print(SesAuthENCKey)

SesAuthMACKey = generate_sesion_key(key_hex, received_RNDA, decrypted_RNDB, 2)

print(SesAuthMACKey)