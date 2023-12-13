from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image, ImageTk
import tkinter as tk
from io import BytesIO

#Function that encrypts selected image
## Returns the original image and the encrypted image
def encrypt_image(input_path, output_path, key):
    image = Image.open(input_path)
    image_bytes = image.tobytes()

    #Choose what encryption mode to use.
    ##Default is ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    padded_data = pad(image_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    encrypted_image = Image.frombytes(image.mode, image.size, encrypted_data)
    encrypted_image.save(output_path)

    return image, encrypted_image

if __name__ == "__main__":
    key = get_random_bytes(16)

    #Enter the image to be encrypted here
    input_image_path = ""
    encrypted_image_path = "encrypted_output.bmp"

    original_image, encrypted_image = encrypt_image(input_image_path, encrypted_image_path, key)

    # Display the images using tkinter
    root = tk.Tk()
    root.title("Encryption of Image")

    original_image_label = tk.Label(root, text="Original Image")
    original_image_label.pack()

    original_image_tk = ImageTk.PhotoImage(original_image)
    original_image_label.img = original_image_tk
    original_image_label.config(image=original_image_tk)

    encrypted_image_label = tk.Label(root, text="Encrypted Image")
    encrypted_image_label.pack()

    encrypted_image_tk = ImageTk.PhotoImage(encrypted_image)
    encrypted_image_label.img = encrypted_image_tk
    encrypted_image_label.config(image=encrypted_image_tk)

    root.mainloop()
