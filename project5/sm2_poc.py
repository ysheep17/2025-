# sm2_poc.py
# SM3 + SM2 (sm2p256v1) reference implementation + PoC for nonce reuse attack
# Pure Python (educational / testing). DO NOT USE in production as-is.

from typing import Tuple
import os
import struct
import hashlib

# -------------------------
# Minimal SM3 implementation (educational, based on spec)
# For production replace with vetted C library
# -------------------------
def rol32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n))

def sm3_compress(V: list, block: bytes) -> list:
    # V: list of 8 uint32
    # block: 64 bytes
    W = [0]*68
    W1 = [0]*64
    w = list(struct.unpack('>16I', block))
    for i in range(16):
        W[i] = w[i]
    def P0(x): return x ^ rol32(x,9) ^ rol32(x,17)
    def P1(x): return x ^ rol32(x,15) ^ rol32(x,23)
    for j in range(16,68):
        W[j] = (P1(W[j-16] ^ W[j-9] ^ rol32(W[j-3],15)) ^ rol32(W[j-13],7) ^ W[j-6]) & 0xFFFFFFFF
    for j in range(64):
        W1[j] = W[j] ^ W[j+4]
    A,B,C,D,E,F,G,H = V
    T_j = [(0x79cc4519 if j<=15 else 0x7a879d8a) & 0xFFFFFFFF for j in range(64)]
    def FF(x,y,z,j): return x ^ y ^ z if j<=15 else ((x & y) | (x & z) | (y & z))
    def GG(x,y,z,j): return x ^ y ^ z if j<=15 else ((x & y) | ((~x) & z))
    for j in range(64):
        SS1 = rol32((rol32(A,12) + E + rol32(T_j[j], j)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ rol32(A,12)
        TT1 = (FF(A,B,C,j) + D + SS2 + W1[j]) & 0xFFFFFFFF
        TT2 = (GG(E,F,G,j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = rol32(B,9)
        B = A
        A = TT1
        H = G
        G = rol32(F,19)
        F = E
        E = P0(TT2)
    Vn = [(V[i] ^ v) & 0xFFFFFFFF for i,v in enumerate([A,B,C,D,E,F,G,H])]
    return Vn

def sm3_hash(msg: bytes) -> bytes:
    # simple SM3 hash: pad and compress
    # IV
    V = [0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E]
    ml = len(msg) * 8
    msg += b'\x80'
    # pad with zero bytes until length ≡ 56 (mod 64)
    while (len(msg) % 64) != 56:
        msg += b'\x00'
    msg += struct.pack('>Q', ml)
    for i in range(0, len(msg), 64):
        V = sm3_compress(V, msg[i:i+64])
    return b''.join(struct.pack('>I', x) for x in V)

# helper to compute ZA (user id) per SM2 spec omitted here for simplicity
def sm2_hash_msg(msg: bytes) -> bytes:
    # For demo, we hash msg directly with SM3 (real SM2 uses ZA = Hash(ENTLA||ID||a..))
    return sm3_hash(msg)

# -------------------------
# Elliptic curve parameters for sm2p256v1
# -------------------------
# All values in decimal integers
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
# Note: these are standard SM2 curve params

# -------------------------
# Finite field helpers
# -------------------------
def mod_inv(x: int, m: int) -> int:
    # modular inverse
    return pow(x, -1, m)

# -------------------------
# EC point operations (affine)
# -------------------------
Point = Tuple[int,int]
O = (None, None)  # point at infinity

def is_inf(P: Point) -> bool:
    return P[0] is None and P[1] is None

def point_add(P: Point, Q: Point) -> Point:
    if is_inf(P): return Q
    if is_inf(Q): return P
    x1,y1 = P
    x2,y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return O
        else:
            return point_double(P)
    lam = ((y2 - y1) * mod_inv((x2 - x1) % p, p)) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3,y3)

def point_double(P: Point) -> Point:
    if is_inf(P): return P
    x1,y1 = P
    lam = ((3*x1*x1 + a) * mod_inv((2*y1) % p, p)) % p
    x3 = (lam*lam - 2*x1) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3,y3)

def scalar_mult(k: int, P: Point) -> Point:
    # double-and-add
    if k % n == 0 or is_inf(P):
        return O
    if k < 0:
        # kP = -k(-P)
        return scalar_mult(-k, (P[0], (-P[1])%p))
    R = O
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_double(Q)
        k >>= 1
    return R

# -------------------------
# SM2 key gen, sign, verify
# -------------------------
def gen_keypair() -> Tuple[int, Point]:
    d = int.from_bytes(os.urandom(32), 'big') % n
    if d == 0:
        return gen_keypair()
    P = scalar_mult(d, (Gx,Gy))
    return d, P

def sm2_sign(msg: bytes, dA: int, k: int = None) -> Tuple[int,int]:
    """
    SM2 signing:
    - msg: raw message (we call sm2_hash_msg internally to get e)
    - dA: private key
    - k: optional ephemeral nonce (if None, random is generated)
    returns (r,s)
    """
    e = int.from_bytes(sm2_hash_msg(msg), 'big') % n
    while True:
        if k is None:
            k = int.from_bytes(os.urandom(32), 'big') % n
        if k == 0: 
            k = None
            continue
        x1,y1 = scalar_mult(k, (Gx,Gy))
        r = (e + x1) % n
        if r == 0 or r + k == n:
            k = None
            continue
        inv = mod_inv((1 + dA) % n, n)
        s = (inv * (k - r * dA)) % n
        if s == 0:
            k = None
            continue
        return r, s

def sm2_verify(msg: bytes, sig: Tuple[int,int], PA: Point) -> bool:
    r,s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    e = int.from_bytes(sm2_hash_msg(msg), 'big') % n
    t = (r + s) % n
    if t == 0:
        return False
    x1,y1 = point_add(scalar_mult(s, (Gx,Gy)), scalar_mult(t, PA))
    R = (e + x1) % n
    return R == r

# -------------------------
# PoC: recover private key when nonce k is reused for two different messages
# Suppose two signatures (r1,s1) for m1 and (r2,s2) for m2 were produced with same k.
# Derivation (SM2):
# s = (1 + d)^-1 (k - r d)  => k = s*(1 + d) + r d = s + d*(s + r)
# So for two signatures k equal -> s1 + d*(s1+r1) = s2 + d*(s2+r2)
# => d * (s1 + r1 - s2 - r2) = s2 - s1  (mod n)
# => d = (s2 - s1) * inv(s1 + r1 - s2 - r2) mod n
# -------------------------
def recover_privkey_from_nonce_reuse(sig1: Tuple[int,int], msg1: bytes,
                                     sig2: Tuple[int,int], msg2: bytes) -> int:
    r1,s1 = sig1
    r2,s2 = sig2
    # check not same signature
    if (r1 == r2) and (s1 == s2):
        raise ValueError("Signatures identical; no info")
    # compute numerator and denominator mod n
    num = (s2 - s1) % n
    den = (s1 + r1 - s2 - r2) % n
    if den == 0:
        raise ValueError("Denominator zero; cannot recover")
    d = (num * mod_inv(den, n)) % n
    return d

# -------------------------
# Demo
# -------------------------
def demo_nonce_reuse_attack():
    print("=== Demo: nonce (k) reuse attack on SM2 ===")
    # generate keypair
    dA, PA = gen_keypair()
    print("Generated private key dA (hex):", hex(dA))
    print("Public key PA:", (hex(PA[0]), hex(PA[1])))
    # choose a fixed k to simulate bad RNG
    bad_k = int.from_bytes(b'\x01'*32, 'big') % n
    msg1 = b"Message One"
    msg2 = b"Message Two"
    sig1 = sm2_sign(msg1, dA, k=bad_k)
    sig2 = sm2_sign(msg2, dA, k=bad_k)
    print("Sig1:", sig1)
    print("Sig2:", sig2)
    # attacker only knows PA, msg1,msg2 and sig1,sig2 (and assumes k reused)
    # recover private key
    recovered = recover_privkey_from_nonce_reuse(sig1, msg1, sig2, msg2)
    print("Recovered d (hex):", hex(recovered))
    print("Matches original?", recovered == dA)
    # Demonstrate forging a signature using recovered key (on arbitrary message) - local test only
    forged_msg = b"Forged message"
    forged_sig = sm2_sign(forged_msg, recovered)  # using correct signing with recovered private key
    ok = sm2_verify(forged_msg, forged_sig, scalar_mult(dA, (Gx,Gy)))
    print("Forged signature OK?", ok)
    print("=== End demo ===")

if __name__ == "__main__":
    demo_nonce_reuse_attack()
