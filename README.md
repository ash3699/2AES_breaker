<h1 align="center" id="title">Man-in-the-Middle AES Encryption attack</h1>

<p id="description">The code reads plaintexts and ciphertexts from the specified files. It performs a man-in-the-middle attack by attempting to find a pair of keys that can be used for encryption and decryption. If successful it prints the keys in both byte and hex formats as well as stores the decrypted secret message in a new text file. 
<p>`2aesPlaintexts.txt`: File containing plaintexts for the man-in-the-middle attack.</p> 
<p>`2aesCiphertexts.txt`: File containing corresponding ciphertexts and one ciphertext of secret message for the man-in-the-middle attack.</p> 
<p>`2aesSecretMessage.txt`: The code saves the decrypted secret message in this file.</p></p>

<h2>🛠️ Installation Steps:</h2>

<p>1. Install the required library using</p>

```
pip install cryptography
```
<p>2. Place your plaintexts in a file named 2aesPlaintexts.txt and ciphertexts in a file named 2aesCiphertexts.txt and store it in the same directory as the python code.</p>

<p>2. Run the code using the command</p>

```
python3 CS23MTECH11004_PROGHW2B.py
```