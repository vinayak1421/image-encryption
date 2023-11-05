from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
from Crypto.Cipher import Blowfish
from Crypto import Random

key = b'SecretKey'


# Generate a random initialization vector (IV)
def generate_iv():
    return Random.new().read(Blowfish.block_size)

# Pad the text to be a multiple of the block size
def pad(text):
    block_size = Blowfish.block_size
    return text + (block_size - len(text) % block_size) * b"\0"

# Remove the padding from decrypted text
def unpad(text):
    return text.rstrip(b"\0")

# Encrypt text with Blowfish
def encrypt_text(text, key):
    iv = generate_iv()
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded_text = pad(text)
    ciphertext = iv + cipher.encrypt(padded_text)
    return ciphertext

# Decrypt text with Blowfish
def decrypt_text(ciphertext, key):
    iv = ciphertext[:Blowfish.block_size]
    ciphertext = ciphertext[Blowfish.block_size:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    return unpad(decrypted_text)


# Encrypt an image using AES
def encrypt_image(input_image_path, output_image_path, key):
    try:
        # Generate an initialization vector (IV)
        iv = get_random_bytes(16)

        # Create an AES cipher object
        cipher = AES.new(key, AES.MODE_CFB, iv)

        # Read the input image
        with open(input_image_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt the image data
        encrypted_data = cipher.encrypt(plaintext)

        encrypted_data1=encrypt_text(encrypted_data,key)


        # Write the encrypted data to the output image
        with open(output_image_path, 'wb') as f:
            f.write(iv)
            f.write(encrypted_data1)

        print("Image encrypted and saved as", output_image_path)

    except Exception as e:
        print("Error:", e)

# Decrypt an image using AES
def decrypt_image(input_image_path, output_image_path, key):
    try:
        # Open the encrypted image
        with open(input_image_path, 'rb') as f:
            iv = f.read(16)
            ciphertext1 = f.read()

            ciphertext=decrypt_text(ciphertext1,key)

        # Create an AES cipher object
        cipher = AES.new(key, AES.MODE_CFB, iv)

        # Decrypt the image data
        decrypted_data = cipher.decrypt(ciphertext)

        # Write the decrypted data to the output image
        with open(output_image_path, 'wb') as f:
            f.write(decrypted_data)

        print("Image decrypted and saved as", output_image_path)

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    input_image = "D:\iss\image.jpg"
    encrypted_image = "D:\iss\encrypted_image.jpg"
    decrypted_image = "D:\iss\decrypted_image.jpg"
    
    # AES key (must be 16, 24, or 32 bytes long)
    key = b'0123456789123456'

    # Encrypt the image
    encrypt_image(input_image, encrypted_image, key)

    # Decrypt the image
    decrypt_image(encrypted_image, decrypted_image, key)
