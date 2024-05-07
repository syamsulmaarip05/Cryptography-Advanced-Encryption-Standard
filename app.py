import os
from flask import Flask, render_template, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

def encrypt_AES(key, plaintext):
    iv = os.urandom(16)  # Membuat IV secara acak
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()  #
    return ciphertext.hex()

def decrypt_AES(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        key = (request.form['key'][:16].ljust(16)).encode('utf-8')

        if 'Encrypt' in request.form:
            message = request.form['message']
            encrypted_message = encrypt_AES(key, message)
            return render_template('index.html', encrypted_message=encrypted_message, wrap_text=True)

        elif 'Decrypt' in request.form:
            ciphertext = bytes.fromhex(request.form['message'])
            iv = ciphertext[:16]  # Mendapatkan IV dari ciphertext
            decrypted_message = decrypt_AES(key, iv, ciphertext[16:])  # Menggunakan IV yang didapat
            return render_template('index.html', decrypted_message=decrypted_message, wrap_text=True)

    return render_template('index.html', wrap_text=True)

if __name__ == '__main__':
    app.run(debug=True)
