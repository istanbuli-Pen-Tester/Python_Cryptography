# Lock & Key – DES + RSA (keygen + sign/verify using Square & Multiply)
# Coursework demo (textbook crypto).

import math
import hashlib

# ==================== DES  ====================
def DES(text, K):# text is the message + K is key
   
    import re

    
    def _bytes_to_bits(b): #b is array of bytes + this function turns each byte to bit then flip becuase the DES and the pyhton form are oppisite
        out = [] # an empty array
        for x in b:# x is each element of b 
            for bit in range(7, -1, -1):# a loop that shift the bits and then takes the first one then shift again to take the next 7 to start from left -1 to stop at 0 -1 is --
                out.append((x >> bit) & 1)#two loops one go through bytes and one go through each bit in 1 byte = 8 
        return out #return the bits that resulted

    def _bits_to_bytes(bits): # in bits array
        assert len(bits) % 8 == 0 #check for right size
        out = bytearray() #array to save the result in
        for i in range(0, len(bits), 8):#go through array of bits
            val = 0
            for bb in bits[i:i+8]:# fill new array with the value of each 8 bits bb is each bit in the current byte
                val = (val << 1) | bb # val to save each bit untill its 8 bits
            out.append(val) #put the value in out
        return bytes(out)# return all bytes 

    def _permute(bits, table): # to turn the DES tablse to indixes table to do permutations
        return [bits[i] for i in table]

    def _xor(a, b): # xor bit by bit
        return [(x ^ y) for x, y in zip(a, b)] # a first array b is secound array // x is first bit of a // y is first bit of y // (^) XOR bit  

    def _left_rotate(lst, n): #rotate bit by bit // n is how much the rotation // lst is the array of numbers
        n %= len(lst) # make sure the n is less then the array size
        return lst[n:] + lst[:n]# return the list after n + before to complete the rotations

    # ---------- DES tables ----------
    IP = [
        57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
        56,48,40,32,24,16,8,0, 58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6
    ]
    FP = [
        39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30,
        37,5,45,13,53,21,61,29, 36,4,44,12,52,20,60,28,
        35,3,43,11,51,19,59,27, 34,2,42,10,50,18,58,26,
        33,1,41,9,49,17,57,25, 32,0,40,8,48,16,56,24
    ]
    E = [
        31,0,1,2,3,4, 3,4,5,6,7,8, 7,8,9,10,11,12,
        11,12,13,14,15,16, 15,16,17,18,19,20, 19,20,21,22,23,24,
        23,24,25,26,27,28, 27,28,29,30,31,0
    ]
    P = [
        15,6,19,20,28,11,27,16, 0,14,22,25,4,17,30,9,
        1,7,23,13,31,26,2,8, 18,12,29,5,21,10,3,24
    ]
    SBOXES = [
        [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
         [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
         [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
         [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
         [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
         [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
         [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
         [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
         [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
         [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
         [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
         [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
         [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
         [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
         [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
         [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
         [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
         [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
         [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
         [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
         [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
         [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
         [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
         [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
         [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    ]
    PC1 = [
        56,48,40,32,24,16,8, 0,57,49,41,33,25,17,
        9,1,58,50,42,34,26, 18,10,2,59,51,43,35,
        62,54,46,38,30,22,14, 6,61,53,45,37,29,21,
        13,5,60,52,44,36,28, 20,12,4,27,19,11,3
    ]
    PC2 = [
        13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,
        25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,
        50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31
    ]
    ROT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    def _sbox_sub(e48):#takes the row from outer bits (first and last) / column middle 4 and take the adjecent value
        #e48 array of 48 resulting from key adjustments
        out = [0]*32 #array of 32
        for box in range(8):# the 8 Sboxes 
            i = box*6 # current 6-bit chuunk start
            b0,b1,b2,b3,b4,b5 = e48[i:i+6] #the 6 buts for this S-box chunk starts inside e48
            row = (b0 << 1) | b5 # row is determined by first and last box
            col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4 #colm detemined by the 4 bits left
            val = SBOXES[box][row][col] # get the val = value from the boxes
            j = box*4 # save 4 bit output in their chunk of out
            #save each bit in its place in out
            out[j+0] = (val >> 3) & 1
            out[j+1] = (val >> 2) & 1
            out[j+2] = (val >> 1) & 1
            out[j+3] = (val >> 0) & 1
        return out

    def _f(r32, rk48): # r32 the righ half of the block // rk48 = 48 bits round key 
        e = _permute(r32, E)# do first premutation // r32 > 48 bits // e is the expantion boxes
        e = _xor(e, rk48)#xor with the key // e is the 48 bit of r32  
        s = _sbox_sub(e)# do S boxes to make the half 32 again
        return _permute(s, P) # do final premutation // p is pboxes

    def _subkeys_from_key(key64_bits):# gets 16 keys from one
        k56 = _permute(key64_bits, PC1)# 64 -> 56 sboxes // key64 the main key // trun it to 56 bit key 
        C, D = k56[:28], k56[28:] #save the first half in c and the scound half in d
        subs = [] #new array
        for r in ROT: #rotate based on the ROT box > ROT box is made because the amount of routation depended on which round 
            C = _left_rotate(C, r)
            D = _left_rotate(D, r)
            subs.append(_permute(C + D, PC2)) #56 -> 48 sboxes like // subs has 16 keys
        return subs

    def _des_block(bits64, subkeys, decrypt=False):
        state = _permute(bits64, IP)#initial permutation 
        L, R = state[:32], state[32:] #split
        order = list(reversed(subkeys)) if decrypt else subkeys # if encrypt go subkeys 1>16 // if decrypt go subkeys 16>1
        for rk in order: #16 rounds // rk is the current key in the array order
            f = _f(R, rk) #expand- xor key- sboxes-pboxes // betwen right and this round key rk
            L, R = R, _xor(L, f) #swap +mix
        preout = R + L# swap after all rounds // because the last round isnt swapped
        return _permute(preout, FP) # final permutation

    # ---------- ECB helper ----------
    def _des_ecb_oneblock(pt8, key_hex, decrypt=False):# if the input is 16 hex char // pt8 is 8 bytes text // key_hex is the key // if we want to encrypt or decypt
        if len(pt8) != 8:# if the size is wrong then there is an error
            raise ValueError("ECB one-block needs exactly 8 bytes.")
        key_bits = _bytes_to_bits(bytes.fromhex(key_hex))# turn the key_hex into bits format
        subs = _subkeys_from_key(key_bits)# get sub keys from the main key
        pt_bits = _bytes_to_bits(pt8) # turn the input into bits
        ct_bits = _des_block(pt_bits, subs, decrypt=decrypt)# do the encryption or the decryption
        return _bits_to_bytes(ct_bits) # return the resut into bytes

    # ---------- CBC+CTS (fallback for arbitrary text) ----------
    BLOCK = 8
    def _cbc_cts_encrypt(plaintext_bytes, key_hex, iv_hex="0000000000000000"):
        key_bits = _bytes_to_bits(bytes.fromhex(key_hex))
        subs = _subkeys_from_key(key_bits)
        iv = bytes.fromhex(iv_hex)
        prev_bits = _bytes_to_bits(iv)

        out = bytearray()
        n = len(plaintext_bytes)
        q, r = divmod(n, BLOCK)
        blocks = [plaintext_bytes[i*BLOCK:(i+1)*BLOCK] for i in range(q)]
        tail = plaintext_bytes[q*BLOCK:] if r else b""

        upto = len(blocks) if r == 0 else max(0, len(blocks)-1)
        for i in range(upto):
            p_bits = _bytes_to_bits(blocks[i])
            x = _xor(p_bits, prev_bits)
            c_bits = _des_block(x, subs, decrypt=False)
            out += _bits_to_bytes(c_bits)
            prev_bits = c_bits

        if r == 0:
            if len(blocks) > upto:
                p_bits = _bytes_to_bits(blocks[-1])
                x = _xor(p_bits, prev_bits)
                c_bits = _des_block(x, subs, decrypt=False)
                out += _bits_to_bytes(c_bits)
            return bytes(out)

        last_full = blocks[-1] if blocks else b"\x00"*BLOCK
        p_full_bits = _bytes_to_bits(last_full)
        x_full = _xor(p_full_bits, prev_bits)
        c_full_bits = _des_block(x_full, subs, decrypt=False)
        c_full = _bits_to_bytes(c_full_bits)

        c_n = c_full[:r]
        stolen = tail + c_full[r:]
        stolen_bits = _bytes_to_bits(stolen)
        x_stolen = _xor(stolen_bits, prev_bits)
        c_n_1_bits = _des_block(x_stolen, subs, decrypt=False)
        c_n_1 = _bits_to_bytes(c_n_1_bits)

        return bytes(out + c_n_1 + c_n)

    def _cbc_cts_decrypt(ciphertext_bytes, key_hex, iv_hex="0000000000000000"):
        key_bits = _bytes_to_bits(bytes.fromhex(key_hex))
        subs = _subkeys_from_key(key_bits)
        iv = bytes.fromhex(iv_hex)
        prev_bits = _bytes_to_bits(iv)

        n = len(ciphertext_bytes)
        if n == 0:
            return b""
        q, r = divmod(n, BLOCK)
        if r == 0:
            out = bytearray()
            for i in range(0, n, BLOCK):
                c_bits = _bytes_to_bits(ciphertext_bytes[i:i+BLOCK])
                t = _des_block(c_bits, subs, decrypt=True)
                p_bits = _xor(t, prev_bits)
                out += _bits_to_bytes(p_bits)
                prev_bits = c_bits
            return bytes(out)

        full = (n // BLOCK) * BLOCK
        c_prefix = ciphertext_bytes[:full - BLOCK]
        c_n_1 = ciphertext_bytes[full - BLOCK: full]
        c_n = ciphertext_bytes[full:]

        out = bytearray()
        for i in range(0, len(c_prefix), BLOCK):
            c_bits = _bytes_to_bits(c_prefix[i:i+BLOCK])
            t = _des_block(c_bits, subs, decrypt=True)
            p_bits = _xor(t, prev_bits)
            out += _bits_to_bytes(p_bits)
            prev_bits = c_bits

        c_full_bits = _bytes_to_bits(c_n_1)
        t = _des_block(c_full_bits, subs, decrypt=True)
        p_stolen_bits = _xor(t, prev_bits)
        p_stolen = _bits_to_bytes(p_stolen_bits)

        rlen = len(c_n)
        p_n = p_stolen[:rlen]

        c_full_bytes = c_n + p_stolen[rlen:]
        c_full_bits2 = _bytes_to_bits(c_full_bytes)
        t2 = _des_block(c_full_bits2, subs, decrypt=True)
        p_n_1_bits = _xor(t2, prev_bits)
        p_n_1 = _bits_to_bytes(p_n_1_bits)

        return bytes(out + p_n_1 + p_n)

    # ---------- Decide mode ----------
    K = K.strip() # remove spaces from the key input
    if len(K) != 16:
        print("Error: key must be 16 hex chars (64 bits incl. parity).")
        return ""

    is_hex_block = bool(re.fullmatch(r"[0-9A-Fa-f]{16}", text.strip())) #if the message is 16 hex if yes go to one block if no > cbc+cts
    if is_hex_block: # if size is 16 hex
        pt = bytes.fromhex(text.strip()) # turn it into bytes 
        ct = _des_ecb_oneblock(pt, K, decrypt=False) #encypt the message // pt is bit of text // k > key 
        print("Ciphertext (hex):", ct.hex().upper())# print the encrypted message
        rec = _des_ecb_oneblock(ct, K, decrypt=True) # decrypt the message // pt is bit of text // k > key 
        print("Recovered plaintext (hex):", rec.hex().upper())# print recovered message
        return ct.hex().upper()
    # this part is for cbc more then 16 hex
    pt_bytes = text.encode("utf-8")
    ct = _cbc_cts_encrypt(pt_bytes, K, iv_hex="0000000000000000")
    rec = _cbc_cts_decrypt(ct, K, iv_hex="0000000000000000")
    try:
        rec_txt = rec.decode("utf-8")
    except UnicodeDecodeError:
        rec_txt = rec.decode("utf-8", errors="ignore")

    print("Ciphertext (hex):", ct.hex().upper())
    print("Recovered plaintext:", rec_txt)
    return ct.hex().upper()

# ==================== RSA helpers ====================

def prime_c(num: int) -> int:
    """Return 1 if prime, 0 otherwise (trial division up to sqrt)."""
    if num < 2:
        print(f"The number {num} isnt a prime.")
        return 0
    if num % 2 == 0:
        if num == 2:
            print(f"The number {num} is a prime.")
            return 1
        print(f"The number {num} isnt a prime.")
        return 0
    sqrt_sq = math.isqrt(num)
    for i in range(3, sqrt_sq + 1, 2):
        if num % i == 0:
            print(f"The number {num} isnt a prime.")
            return 0
    print(f"The number {num} is a prime.")
    return 1

def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No multiplicative inverse exists (gcd != 1).")
    return x % m

def read_10_digit_prime(prompt: str) -> int:
    while True:
        num_str = input(prompt).strip()
        if not num_str.isdigit():
            print("Please enter digits only.")
            continue
        num = int(num_str)
        if num < 1_000_000_000 or num > 9_999_999_999:
            print("Number must be exactly 10 digits.")
            continue
        if prime_c(num) == 1:
            return num

# -------------------- Square & Multiply --------------------
def square_and_multiply(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation using the Square & Multiply algorithm."""
    base %= mod
    result = 1
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod   # multiply when bit is 1
        base = (base * base) % mod           # square every round
        exp >>= 1                             # shift to next bit
    return result

# Hash -> int
def _sha256_int(msg: str) -> int:
    h = hashlib.sha256(msg.encode("utf-8")).digest()
    return int.from_bytes(h, "big")

def rsa_sign_message(msg: str, d: int, n: int) -> int:
    h = _sha256_int(msg) % n
    return square_and_multiply(h, d, n)      # <-- uses Square & Multiply

def rsa_verify_message(msg: str, sig: int, e: int, n: int) -> bool:
    h = _sha256_int(msg) % n
    return square_and_multiply(sig, e, n) == h  # <-- uses Square & Multiply

def rsa_keygen_and_auth_flow():
    print("RSA key generation is required")
    print("Input two prime numbers (10 digits each).")

    p = read_10_digit_prime("number 1: ")
    q = read_10_digit_prime("number 2: ")
    while q == p:
        print("number 2 must be different from number 1.")
        q = read_10_digit_prime("number 2: ")

    # public exponent e
    while True:
        try:
            e = int(input("Provide the public exponent (e): ").strip())
            if e <= 1:
                print("e must be > 1.")
                continue
            break
        except ValueError:
            print("Enter e as an integer (e.g., 65537).")

    n = p * q
    phi = (p - 1) * (q - 1)
    g = math.gcd(e, phi)
    if g != 1:
        print(f"gcd(e, φ(n)) = {g} ≠ 1. Choose a different e.")
        return
    try:
        d = modinv(e, phi)
    except ValueError as err:
        print(err)
        return
    print("\n--- RSA Key ---")
    print("Public key (n, e):")
    print("n =", n)
    print("e =", e)
    print("Private key d:")
    print("d =", d)

    # Sign & Verify
    msg = input("\nEnter a message to digitally sign: ")
    sig = rsa_sign_message(msg, d, n)
    print("Signature (decimal):", sig)
    print("Signature (hex):", hex(sig)[2:].upper())

    ok = rsa_verify_message(msg, sig, e, n)
    print("Signature verification:", "VALID" if ok else "INVALID")

# ==================== Crypto Analysis ====================
def rsa_short_message_attack():
    print("=== RSA Short-Message Cryptanalysis ===")
    try:
        e = int(input("Public exponent e: ").strip())
        n = int(input("Modulus n (use 2-digit for demo): ").strip())
        c = int(input("Ciphertext integer c: ").strip())
    except ValueError:
        print("Please enter integers for e, n, c.")
        return

    # Method 1 — Preimage brute force on the tiny domain
    found = None
    for m in range(n):
        if pow(m, e, n) == c:
            found = m
            print(f"[Brute force] Found plaintext m = {m}")
            break
    if found is None:
        print("[Brute force] Not found in 0..n-1")

    # Method 2 — Factor n, compute d, then decrypt
    p = None
    for t in range(2, int(math.isqrt(n)) + 1):
        if n % t == 0:
            p = t
            q = n // t
            break
    if p is None:
        print("[Factorization] Could not factor n (try a smaller n).")
        return

    phi = (p - 1) * (q - 1)
    try:
        d = modinv(e, phi)
    except ValueError:
        print(f"[Factorization] gcd(e, φ(n)) ≠ 1 → cannot compute d.")
        return

    m2 = pow(c, d, n)
    print(f"[Factorization] n = {p}×{q}, φ(n) = {phi}, d = {d}")
    print(f"[Factorization] Decrypted plaintext m = {m2}")


# ==================== MAIN MENU ====================

def main():
    print("***** LOCK && KEY *****")
    print("1. Confidentiality Only (DES)")
    print("2. Authentication Only (RSA Sign/Verify)")
    print("3. Confidentiality & Authentication")
    print("4. RSA cryptanalysis  (stub)")
    

    try:
        choice = int(input("Enter your choice: "))
    except ValueError:
        return

    if choice == 1:
        text = input("Enter the message you want to encrypt: ")
        K = input("Enter the key (in hex, e.g. 133457799BBCDFF1): ")
        En = DES(text, K)
        print("Encryption finished. Output:", En)

    elif choice == 2:
        rsa_keygen_and_auth_flow()

    elif choice == 3:
        text = input("Enter the message you want to encrypt: ")
        K = input("Enter the key (in hex, e.g. 133457799BBCDFF1): ")
        En = DES(text, K)
        print("Encryption finished. Output:", En)
        print("\nNow generating/using RSA keys for a digital signature of your original message...")
        rsa_keygen_and_auth_flow()

    elif choice == 4:
        rsa_short_message_attack()



if __name__ == "__main__":
    main()
