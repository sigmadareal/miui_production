from flask import Flask, request, send_file, jsonify, make_response
import os
import io
import filetype
from Crypto.Cipher import AES
from Crypto.Util import Counter
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 600 * 1024 * 1024  # 50 MB
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
DECRYPTED_FOLDER = os.path.join(os.path.dirname(__file__), 'decrypted')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

sAesIv = 22696201676385068962342234041843478898
secretKey = b'0\x82\x04l0\x82\x03T\xa0\x03\x02\x01\x02\x02\t\x00'

# Decrypt header-only (used for .lsav)
def decrypt_file_header_bytes(data_bytes: bytes) -> bytes:
    size = len(data_bytes)
    header_size = max(min(1024, size), 16)
    ctr = Counter.new(128, initial_value=sAesIv)
    aes = AES.new(secretKey, mode=AES.MODE_CTR, counter=ctr)
    return aes.decrypt(data_bytes[:header_size]) + data_bytes[header_size:]

# Decrypt whole file (used for .lsa)
def decrypt_file_bytes(data_bytes: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=sAesIv)
    aes = AES.new(secretKey, mode=AES.MODE_CTR, counter=ctr)
    return aes.decrypt(data_bytes)

@app.route("/", methods=["GET"]) 
def index(): 
    return "OK"

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    filename = file.filename or 'uploaded'
    data = file.read()
    ext = filename.split('.')[-1].lower()
    if ext == 'lsa':
        decrypted = decrypt_file_bytes(data)
    elif ext == 'lsav':
        decrypted = decrypt_file_header_bytes(data)
    else:
        return jsonify({'error': 'Unsupported file type'}), 400

    guessed_ext = filetype.guess_extension(decrypted[:1024]) or 'bin'
    outname = f"{os.path.splitext(filename)[0]}.{guessed_ext}"

    # Save decrypted file for debugging / download if desired
    decrypted_path = os.path.join(DECRYPTED_FOLDER, outname)
    with open(decrypted_path, 'wb') as f_out:
        f_out.write(decrypted)

    # Determine content type
    kind = filetype.guess(decrypted[:1024])
    content_type = kind.mime if kind else 'application/octet-stream'

    bio = io.BytesIO(decrypted)
    bio.seek(0)
    response = make_response(send_file(bio, mimetype=content_type, as_attachment=True, download_name=outname))
    response.headers['X-Filename'] = outname
    return response

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({'error': 'File too large. Maximum upload size is 50 MB.'}), 413

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
