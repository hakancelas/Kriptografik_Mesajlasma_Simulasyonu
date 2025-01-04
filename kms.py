from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# AES için şifreleme ve çözme işlemleri
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)  # EAX modu seçildi
    nonce = cipher.nonce                # Şifreleme için kullanılan nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext

def decrypt_message(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# Kullanıcıdan giriş al
key = get_random_bytes(16)  # 16 byte (128-bit) anahtar oluştur
message = input("Şifrelemek istediğiniz mesajı girin: ")

# Şifreleme işlemi
nonce, ciphertext = encrypt_message(key, message)
print(f"\nŞifrelenmiş Mesaj: {base64.b64encode(ciphertext).decode('utf-8')}")

# Çözme işlemi
decrypted_message = decrypt_message(key, nonce, ciphertext)
print(f"\nÇözülmüş Mesaj: {decrypted_message}")