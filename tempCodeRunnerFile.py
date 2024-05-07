        if 'Encrypt' in request.form:
            message = request.form['message']
            try:
                ciphertext = encrypt_AES(key, message)
                return render_template('index.html', encrypted_message=ciphertext.hex(), wrap_text=True)
            except Exception as e:
                return render_template('index.html', error_message=str(e), wrap_text=True)