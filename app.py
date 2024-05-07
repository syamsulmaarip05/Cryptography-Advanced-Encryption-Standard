from flask import Flask, render_template, request, session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)
app.secret_key = "crypto"


def get_random_bytes(length):
    return secrets.token_bytes(length)

def encrypt_AES(key, plaintext):
    iv = get_random_bytes(16)
    print("Generated IV:", iv.hex())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    print("Padded Data:", padded_data.hex())

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print("Ciphertext:", ciphertext.hex())

    session['iv'] = iv  # Simpan IV dalam session
    return ciphertext


def decrypt_AES(key, ciphertext):
    iv = session.get('iv', b'')  # Ambil IV dari session, default b'' jika tidak ada
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded_data.decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        key = (request.form['key'][:16].ljust(16)).encode('utf-8')

        if 'Encrypt' in request.form:
            message = request.form['message']
            ciphertext = encrypt_AES(key, message)
            return render_template('index.html', encrypted_message=ciphertext.hex(), wrap_text=True)

        elif 'Decrypt' in request.form:
            ciphertext = bytes.fromhex(request.form['message'])
            decrypted_message = decrypt_AES(key, ciphertext)
            return render_template('index.html', decrypted_message=decrypted_message, wrap_text=True)

    return render_template('index.html', wrap_text=True)

if __name__ == '__main__':
    app.run(debug=True)
