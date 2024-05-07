from flask import Flask, render_template, request

app = Flask(__name__)
app.secret_key = "cripto"

class LCG:
    def __init__(self, seed, a=100, c=200, m=2**32):
        self.seed = seed
        self.a = a
        self.c = c
        self.m = m

    def generate(self):
        result = (self.a * self.seed + self.c) % self.m
        print("LCG Result:", result)
        self.seed = result
        return self.seed

def encrypt(message, key):
    lcg = LCG(key)
    encrypted_message = bytearray()
    for char in message:
        lcg_value = lcg.generate()
        print("LCG Value:", lcg_value)
        encrypted_char = char ^ lcg_value % 256
        encrypted_message.append(encrypted_char)
        print("Encrypted Char:", encrypted_char)
    return encrypted_message

def decrypt(encrypted_message, key):
    lcg = LCG(key)
    decrypted_message = bytearray()
    for char in encrypted_message:
        lcg_value = lcg.generate()
        decrypted_char = char ^ lcg_value % 256
        decrypted_message.append(decrypted_char)
    return decrypted_message


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        key = int(request.form['key'])
        message = request.form['message']

        # Check if input is hexadecimal, indicating it's encrypted
        try:
            message = bytes.fromhex(message)
            is_encrypted = True
        except ValueError:
            is_encrypted = False

        if is_encrypted:
            # Decrypt the message
            decrypted_message = decrypt(message, key)
            return render_template('index.html', decrypted_message=decrypted_message.decode(), wrap_text=True)

        else:
            # Encrypt the message
            encrypted_message = encrypt(message.encode(), key)
            encrypted_hex = encrypted_message.hex()
            return render_template('index.html', encrypted_message=encrypted_hex, wrap_text=True)

    return render_template('index.html', wrap_text=True)


if __name__ == '__main__':
    app.run(debug=True)
