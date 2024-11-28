from flask import Flask, render_template, request, jsonify
from Feistel import FeistelCipher
import os

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form['action']
        text = request.form['text']
        master_key = request.form['master_key'] if request.form['master_key'] else None

        if action == 'encrypt':
            result = encrypt_text(text, master_key)
        elif action == 'decrypt':
            result = decrypt_text(text, master_key)
        else:
            return jsonify({'error': 'Invalid action'})

        return jsonify({'result': result})
    return render_template('indexUserKM.html')


def encrypt_text(text, master_key):
    cipher = FeistelCipher()
    round_keys = cipher.generate_round_keys(master_key)

    text_bytes = text.encode('utf-8')

    if len(text_bytes) <= 16:
        padded = text_bytes.ljust(16, b'\x00')
        encrypted_data = cipher.encrypt(padded, round_keys)
    else:
        blocks = [text_bytes[i:i + 16].ljust(16, b'\x00') for i in range(0, len(text_bytes), 16)]
        encrypted_blocks = []
        for block in blocks:
            encrypted = cipher.encrypt(block, round_keys)
            encrypted_blocks.append(encrypted)
        encrypted_data = b''.join(encrypted_blocks)

    result = {
        'original': text,
        'encrypted': encrypted_data.hex(),
    }

    if cipher.last_generated_master_key:
        result['generated_master_key'] = cipher.last_generated_master_key.hex()

    return result


def decrypt_text(encrypted_hex, master_key):
    cipher = FeistelCipher()
    round_keys = cipher.generate_round_keys(master_key)

    try:
        encrypted_data = bytes.fromhex(encrypted_hex)
    except ValueError:
        return {'error': 'Invalid hexadecimal input'}

    if len(encrypted_data) <= 16:
        decrypted_data = cipher.decrypt(encrypted_data, round_keys)
    else:
        blocks = [encrypted_data[i:i + 16] for i in range(0, len(encrypted_data), 16)]
        decrypted_blocks = []
        for block in blocks:
            decrypted = cipher.decrypt(block, round_keys)
            decrypted_blocks.append(decrypted)
        decrypted_data = b''.join(decrypted_blocks)

    try:
        decrypted_text = decrypted_data.rstrip(b'\x00').decode('utf-8')
    except UnicodeDecodeError:
        return {'error': 'Decryption failed. Invalid key or corrupted data.'}

    result = {
        'encrypted': encrypted_hex,
        'decrypted': decrypted_text
    }

    if cipher.last_generated_master_key:
        result['generated_master_key'] = cipher.last_generated_master_key.hex()

    return result


if __name__ == '__main__':
    app.run(debug=True)