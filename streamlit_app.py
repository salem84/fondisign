import base64
import streamlit as st
import hashlib
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

class Config:
    @property
    def tenant_id(self):
        tenant_id = self.read_from_env_or_secrets('AZURE_TENANT_ID')       
        os.environ['AZURE_TENANT_ID'] = tenant_id
        # Restituisce il tenant_id, o None se non esiste
        return tenant_id

    @property
    def client_id(self):
        client_id = self.read_from_env_or_secrets('AZURE_CLIENT_ID')
        os.environ['AZURE_CLIENT_ID'] = client_id
        return client_id
    
    @property
    def client_secret(self):
        client_secret = self.read_from_env_or_secrets('AZURE_CLIENT_SECRET')
        os.environ['AZURE_CLIENT_SECRET'] = client_secret
        return client_secret

    @property
    def azkeyvault_name(self):
        azkeyvault_name = self.read_from_env_or_secrets('AZKEYVAULT_NAME')
        return azkeyvault_name

    @property
    def azkeyvault_key_name(self):
        azkeyvault_key_name = self.read_from_env_or_secrets('AZKEYVAULT_KEY_NAME')
        return azkeyvault_key_name

    def read_from_env_or_secrets(self, key):
        value = os.getenv(key)
        if value is None:
            try:
                value = st.secrets[key]
            except FileNotFoundError:
                print(f'File secrets.toml non esistente')
                value = None
            except KeyError:
                print(f"La variabile {key} non è stata trovata né nelle variabili d'ambiente né nei secrets di Streamlit.")
                value = None
        return value

    def check(self):
        if self.tenant_id is None:
            raise ValueError("Il tenant_id non è stato configurato.")
        if self.client_id is None:
            raise ValueError("Il client_id non è stato configurato.")
        if self.client_secret is None:
            raise ValueError("Il client_secret non è stato configurato.")
        if self.azkeyvault_name is None:
            raise ValueError("Il nome del Key Vault non è stato configurato.")
        if self.azkeyvault_key_name is None:
            raise ValueError("Il nome della chiave nel Key Vault non è stato configurato.")

# ----- FUNZIONI ----- #
def hash_file(file):
    """Genera l'hash SHA-256 del file caricato."""
    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: file.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.digest()

# Funzione per firmare l'hash usando la chiave privata nel Key Vault
def sign_hash_with_private_key(hash_value):
    # Autenticazione tramite DefaultAzureCredential (usa Managed Identity, environment variables, ecc.)
    credential = DefaultAzureCredential()

    key_vault_name = config.azkeyvault_name
    key_name = config.azkeyvault_key_name
    
    # URL del Key Vault
    kv_url = f"https://{key_vault_name}.vault.azure.net"

    # Crea un client per il Key Vault per accedere alla chiave
    key_client = KeyClient(vault_url=kv_url, credential=credential)

    # Recupera la chiave RSA dal Key Vault
    key = key_client.get_key(key_name)

    # Crea un client di crittografia per firmare l'hash
    crypto_client = CryptographyClient(key, credential=credential)

    # Firma l'hash usando la chiave privata nel Key Vault (algoritmo RS256)
    sign_result = crypto_client.sign(SignatureAlgorithm.rs256, hash_value)

    # Restituisce la firma (che è l'hash criptato con la chiave privata)
    return sign_result.signature


# Funzione per ottenere la chiave pubblica dal Key Vault
def verify_signature(original_hash, signature):
    # Autenticazione tramite DefaultAzureCredential (usa Managed Identity, environment variables, ecc.)
    credential = DefaultAzureCredential()

    key_vault_name = config.azkeyvault_name
    key_name = config.azkeyvault_key_name

    # URL del Key Vault
    kv_url = f"https://{key_vault_name}.vault.azure.net"

    # Crea un client per il Key Vault per accedere alla chiave
    key_client = KeyClient(vault_url=kv_url, credential=credential)

    # Recupera la chiave RSA dal Key Vault
    key = key_client.get_key(key_name)

    # Crea un client di crittografia per firmare l'hash
    crypto_client = CryptographyClient(key, credential=credential)

    # Firma l'hash usando la chiave privata nel Key Vault (algoritmo RS256)
    sign_result = crypto_client.verify(SignatureAlgorithm.rs256, original_hash, signature)

    return sign_result.is_valid

#---------------------------------#
#----- INTERFACCIA STREAMLIT -----#
#---------------------------------#

# Verifica configurazione
config = Config()
config.check()

st.title("Fondi Signature🔐")

tabSign, tabVerify = st.tabs(["Genera", "Verifica"])

with tabSign:
    st.header("Genera Signature")
    
    # Caricamento del file da processare
    uploaded_file_tosign = st.file_uploader("Carica un file", type=["xml"], key="file_upload_to_sign")
    

    if st.button("Genera file Signature"):
        file_hash = hash_file(uploaded_file_tosign)

        encrypted_hash_bin = sign_hash_with_private_key(file_hash)
        
        # converti l'hash in base64
        encrypted_hash =  base64.b64encode(encrypted_hash_bin).decode("utf-8")
        st.info("Signature generata con successo!")

        # Crea il file di output con estensione .sig
        sig_filename = uploaded_file_tosign.name + ".sig"
        st.download_button(
            label="Scarica il file firmato",
            data=encrypted_hash,
            file_name=sig_filename,
            mime="application/octet-stream"
        )

with tabVerify:
    st.header("Verifica Signature")

    # Caricamento del file da processare
    uploaded_file_toverify = st.file_uploader("Carica un file", type=["xml"], key="file_upload_to_verify")

    # Caricamento del file Signature
    uploaded_sig = st.file_uploader("Carica il file Signature", type=["sig"], key="sig_upload_to_verify")

    if uploaded_file_toverify:
        file_hash_toverify = hash_file(uploaded_file_toverify)
        # st.info(f"Hash del file caricato: {file_hash_toverify}")

    if uploaded_sig:
        signature_base64 = uploaded_sig.getvalue().decode("utf-8")
        # st.info(f"Signature: {signature_base64}")
        signature = base64.b64decode(signature_base64)

    if st.button("Verifica Signature"):
        is_valid = verify_signature(file_hash_toverify, signature)
        if is_valid:
            st.success("La firma è valida!")
        else:
            st.error("La firma non è valida!")

       