#!/usr/bin/env python
# coding: utf-8

# In[3]:


pip install cryptography


# In[4]:


# Task 1: Try to build or change an existing algorithm to secure message send by the user based on efficiency

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Encrypting the message
def encrypt_message(message, password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=backend
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return urlsafe_b64encode(salt + iv + ciphertext + encryptor.tag).decode()


# In[11]:


# Decrypting the message
def decrypt_message(enc_message, password):
    backend = default_backend()
    decoded_message = urlsafe_b64decode(enc_message.encode())
    salt, iv, ciphertext, tag = decoded_message[:16], decoded_message[16:28], decoded_message[28:-16], decoded_message[-16:]
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Test the functions
if __name__ == "__main__":
    message = "This message is highly confidential."
    password = "security"
    
    enc_message = encrypt_message(message, password)
    print("Encrypted Message:", enc_message)
    
    dec_message = decrypt_message(enc_message, password)
    print("Decrypted Message:", dec_message.decode())


# In[5]:


pip install sklearn


# In[6]:


# Task 2: for User Authentication and Validation

import getpass
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np

# Sample dataset representing user's typing speed patterns (input for ML model)
# This is just a placeholder dataset; in practice, this data would be collected from user behavior
user_data = np.array([
    [0.1, 0.2, 0.15, 0.18, 0.25],  # User 1 typing pattern
    [0.12, 0.22, 0.18, 0.17, 0.24], # User 2 typing pattern
    [0.11, 0.19, 0.16, 0.20, 0.21], # User 3 typing pattern
    # Add more patterns here...
])
labels = np.array([1, 0, 1])  # Labels corresponding to user identity (1 = authorized, 0 = unauthorized)

# Train an ML model to validate user identity
X_train, X_test, y_train, y_test = train_test_split(user_data, labels, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)


# In[7]:


# Simulate user input for authentication
def authenticate_user():
    password = getpass.getpass("Enter your password: ")
    if password == "security":  # Password validation (in practice, use a hash)
        print("Password is correct.")
        return True
    else:
        print("Password is incorrect.")
        return False

def validate_user_typing(typing_pattern):
    # Predict the user's identity based on typing pattern
    prediction = model.predict([typing_pattern])
    if prediction == 1:
        print("User identity validated.")
        return True
    else:
        print("User identity validation failed.")
        return False

if __name__ == "__main__":
    # Authenticate user by password
    if authenticate_user():
        # Simulate a typing pattern for validation (in practice, capture real typing data)
        typing_pattern = [0.1, 0.2, 0.16, 0.19, 0.23]
        validate_user_typing(typing_pattern)


# In[ ]:




