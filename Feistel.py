import os
import hashlib
import pandas as pd


class FeistelCipher:
    def __init__(self,num_rounds = 16 ,key_size_bytes = 8):
        self.num_rounds = num_rounds
        self.key_size_bytes = key_size_bytes
        self.last_generated_master_key = None

    def generate_round_keys(self, master_key_string = None):
        # Convert the input string to bytes

        if master_key_string is None:
            # Generate a new master key
            self.last_generated_master_key = os.urandom(self.key_size_bytes * 2)
            master_key = self.last_generated_master_key
        else:
            try:
                master_key = bytes.fromhex(master_key_string)
            except ValueError:
                # If the string is not valid hex, encode it as UTF-8
                master_key = master_key_string.encode('utf-8')
                self.last_generated_master_key = None

        # Use HKDF to derive a fixed-length key from the master key
        hkdf = hashlib.pbkdf2_hmac('sha512', master_key, b'salt', 100000, dklen=self.key_size_bytes * 2)

        # Use the derived key to generate round keys
        round_keys = []
        for i in range(self.num_rounds):
            # Combine derived key and round number
            round_data = hkdf + i.to_bytes(4, 'big')
            # Use SHA-256 to derive the round key
            round_key = hashlib.sha256(round_data).digest()
            round_keys.append(round_key[:self.key_size_bytes])
        return round_keys

    def xor_with_subkey(self, data, subkey):
        return bytes([b ^ k for b, k in zip(data, subkey)])

    def rotate_bits(self, byte, n): #Dependant Function for rotating each byte
        return ((byte << n) & 0xFF) | (byte >> (8 - n))

    def rotate_each_byte(self, data, round_number): #Permutation Operation
        shift_amount = round_number % 4
        return bytes([self.rotate_bits(b, shift_amount) for b in data])

    def reverse_bytes(self, data): #Reverse using stack (Permutation Operation)
        return data[::-1]

    def invert_bits(self, data): #Inverts each 0 to 1 bit and each 1 to 0 bit (Substitution Operation)
        return bytes([~b & 0xFF for b in data])

    def modular_hex_transform(self, data, round_number): #Substitution Operation
        result = bytearray()
        for byte in data:
            upper_nibble = ((byte >> 4) + round_number) % 16
            lower_nibble = ((byte & 0x0F) + round_number) % 16
            result.append((upper_nibble << 4) | lower_nibble)
        return bytes(result)

    def round(self, L, R, subkey, round_number):
        F = self.xor_with_subkey(R, subkey)
        F = self.rotate_each_byte(F, round_number)
        F = self.reverse_bytes(F)
        F = self.invert_bits(F)
        F = self.modular_hex_transform(F, round_number)
        new_R = bytes([l ^ f for l, f in zip(L, F)])
        return R, new_R

    def encrypt(self, plaintext, round_keys):
        assert len(plaintext) == 16, "Plaintext must be 128 bits (16 bytes)"
        L, R = plaintext[:8], plaintext[8:]

        for round_number, subkey in enumerate(round_keys):
            L, R = self.round(L, R, subkey, round_number)
        return R + L

    def encrypt_trace(self, plaintext, round_keys):
        assert len(plaintext) == 16, "Plaintext must be 128 bits (16 bytes)"
        L, R = plaintext[:8], plaintext[8:]
        trace_data = []

        for round_number, subkey in enumerate(round_keys):
            trace_data.append({
                'Round': round_number + 1,
                'Left Half (L)': L.hex(),
                'Right Half (R)': R.hex(),
                'Subkey': subkey.hex()
            })
            L, R = self.round(L, R, subkey, round_number)

        trace_data.append({'Round': 'Final', 'Left Half (L)': R.hex(), 'Right Half (R)': L.hex(), 'Subkey': 'N/A'})
        self.display_trace(trace_data,"Encryption")
        return R + L, trace_data

    def decrypt(self,ciphertext, round_keys):
        assert len(ciphertext) == 16, "Ciphertext must be 128 bits (16 bytes)"
        L, R = ciphertext[8:], ciphertext[:8]

        for round_number, subkey in reversed(list(enumerate(round_keys))):
            R, L = self.round(R, L, subkey, round_number)

        return L + R

    def decrypt_trace(self, ciphertext, round_keys):
        assert len(ciphertext) == 16, "Ciphertext must be 128 bits (16 bytes)"
        L, R = ciphertext[8:], ciphertext[:8]
        trace_data = []

        for round_number, subkey in reversed(list(enumerate(round_keys))):
            trace_data.append({
                'Round': round_number + 1,
                'Left Half (L)': L.hex(),
                'Right Half (R)': R.hex(),
                'Subkey': subkey.hex()
            })
            R, L = self.round(R, L, subkey, round_number)

        trace_data.append({'Round': 'Final', 'Left Half (L)': L.hex(), 'Right Half (R)': R.hex(), 'Subkey': 'N/A'})
        return L + R, trace_data

    def display_trace(self, trace_data, process_type="Encryption"):
        df = pd.DataFrame(trace_data)
        print(f"\n{process_type} Trace Data (16 Rounds)")
        print(df)