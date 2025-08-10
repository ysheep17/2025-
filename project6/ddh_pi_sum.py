"""
ddh_pi_sum.py

Reference implementation (single-machine simulation) of the DDH-based
Private Intersection-Sum-with-Cardinality protocol (Figure 2, Section 3.1 in
Ion et al., 2019). Meant for research/edu. Not production-ready.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from phe import paillier
import os
import hashlib
import random
from typing import List, Tuple, Dict

# ---------------------------
# Utilities
# ---------------------------

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

# Simplified "hash-to-group" for demo:
# We map identifier -> EC public point by hashing to scalar mod n and multiplying base point.
# (Paper uses hashing-to-curve; here we do scalar-from-hash * G which is acceptable for demo.)
def hash_to_group_point(identifier: bytes, curve=ec.SECP256R1()):
    # use SHA256(seed || identifier) then mod n
    order = curve.key_size  # in bits (256)
    # compute scalar = int(hash) mod curve_order
    h = sha256(identifier)
    # get curve order
    curve_obj = ec.SECP256R1()
    # cryptography doesn't expose order easily; use known prime256v1 order:
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    scalar = int.from_bytes(h, 'big') % n
    if scalar == 0:
        scalar = 1
    # compute point = scalar * G
    priv = ec.derive_private_key(scalar, curve, default_backend())
    pub = priv.public_key()
    return pub  # cryptography public key object representing point

def ec_point_to_bytes(pubkey: ec.EllipticCurvePublicKey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.X962,
                               format=serialization.PublicFormat.UncompressedPoint)

def scalar_exp_point(pubkey: ec.EllipticCurvePublicKey, exponent: int, curve=ec.SECP256R1()):
    """
    compute (point) ^ exponent  in multiplicative notation.
    We implement by extracting affine coords, reconstructing point, and doing scalar multiplication by exponent.
    For demo: convert point to scalar by using its x coord as seed, then perform scalar*G where scalar = discrete_log? 
    Simpler: represent group element as public point P; exponentiation by exponent means scalar_multiplication: (x -> exponent * P)
    cryptography doesn't expose multiply(P, k) directly, but we can:
      - get encoded point, derive its affine x,y? Instead: use ECDH trick:
        Derive shared secret: priv_k * P = k*P
      So we can choose local ephemeral private key with scalar=exponent and do ECDH with P to get k*P's x coord,
      but cryptography only returns shared secret (x coord) not full point. Thus for demo we simulate the group as "scalars * G" only.
    For correctness in protocol simulation: we will represent group elements as scalar*G (i.e., we always create points as scalar*G),
    and exponentiation by exponent corresponds to multiplying the scalar by exponent modulo n.
    """
    # This function assumes input pubkey was created as scalar1 * G.
    # We'll store a special attribute: the public bytes encode scalar*G, but we cannot recover scalar easily.
    # So in our simulation, we will **represent** group elements as integer scalars (mod n) instead of cryptography points.
    raise NotImplementedError("Use ScalarGroup below for cleaner scalar-based simulation.")

# ---------------------------
# Scalar-group lightweight abstraction (for demo)
# We simulate group G as multiples of generator G: group element = s * G, represented by scalar s mod n.
# This is consistent with protocol semantics (we only need to test equality of elements and exponentiation by secret exponents).
# ---------------------------

# prime256v1 order (n)
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def id_to_scalar(identifier: bytes, seed: bytes = b'') -> int:
    # deterministic mapping id -> scalar in [1..N-1]
    h = hashlib.sha256(seed + identifier).digest()
    s = int.from_bytes(h, 'big') % N
    if s == 0:
        s = 1
    return s

class ScalarGroupElem:
    """Represent element s*G by scalar s (mod N)."""
    def __init__(self, s: int):
        self.s = s % N
    def __eq__(self, other):
        if not isinstance(other, ScalarGroupElem):
            return False
        return self.s % N == other.s % N
    def __repr__(self):
        return f"Elem({hex(self.s)})"
    def exponentiate_by(self, exponent: int):
        # (s*G)^{exponent} = (s*exponent) * G
        return ScalarGroupElem((self.s * (exponent % N)) % N)

# ---------------------------
# Protocol roles (P1, P2) simulated locally
# ---------------------------

class Party1:
    def __init__(self, ids: List[bytes], seed: bytes=b''):
        self.ids = ids
        self.seed = seed
        # choose secret exponent k1 in Z_n
        self.k1 = random.randrange(1, N)
        # Z will hold H(vi)^{k1} values (as ScalarGroupElem)
        self.Z = []

    def round1_send(self):
        # compute H(vi) as scalar*G then exponentiate by k1 -> represent as ScalarGroupElem
        self.Z = []
        for v in self.ids:
            s = id_to_scalar(v, seed=self.seed)     # H(v) mapped to scalar s
            elem = ScalarGroupElem(s).exponentiate_by(self.k1)  # H(v)^{k1}
            self.Z.append(elem)
        # shuffle
        random.shuffle(self.Z)
        return self.Z

    def round3_receive_and_compute(self, received_pairs: List[Tuple[ScalarGroupElem, paillier.EncryptedNumber]], paillier_pubkey):
        # received_pairs: list of (H(wj)^{k2}, AEnc(tj))
        # for each, exponentiate first member by k1 to get H(wj)^{k1 k2}
        transformed = []
        for (g_elem, enc_t) in received_pairs:
            gkk = g_elem.exponentiate_by(self.k1)  # now H(wj)^{k1 k2}
            transformed.append((gkk, enc_t))
        # compute intersection J: those indices where gkk in Z
        Zset = {z.s for z in self.Z}  # set of scalars representing Z
        sum_cipher = None
        cnt = 0
        for gkk, enc_t in transformed:
            if gkk.s in Zset:
                cnt += 1
                if sum_cipher is None:
                    sum_cipher = enc_t
                else:
                    sum_cipher = sum_cipher + enc_t  # paillier EncryptedNumber supports addition
        if sum_cipher is None:
            # encrypt zero under P2's pk to return 0
            sum_cipher = paillier_pubkey.encrypt(0)
        # randomize (ARefresh) - with Paillier it's adding encryption of 0 with new randomness
        # In phe, encryption is randomized each time, so re-encrypting same plaintext is enough:
        randomized = paillier_pubkey.encrypt(sum_cipher.ciphertext(False))  # not ideal - phe doesn't provide direct ACRefresh. we'll re-encrypt 0 and add
        # better: add fresh encryption of 0
        zero_enc = paillier_pubkey.encrypt(0)
        refreshed = sum_cipher + zero_enc
        return refreshed, cnt

class Party2:
    def __init__(self, pairs: List[Tuple[bytes, int]], seed: bytes=b''):
        # pairs: list of (w, t)
        self.pairs = pairs
        self.seed = seed
        self.k2 = random.randrange(1, N)
        # will hold paillier keypair later
        self.paillier_pub = None
        self.paillier_priv = None

    def setup_paillier(self, keysize=1024):
        pub, priv = paillier.generate_paillier_keypair(n_length=keysize)
        self.paillier_pub = pub
        self.paillier_priv = priv
        return pub

    def round2_receive_Z_and_respond(self, Z_from_p1: List[ScalarGroupElem]):
        # For each element in Z_from_p1 (which are H(vi)^{k1} = (s * G)^{k1}), exponentiate by k2 -> H(vi)^{k1 k2}
        Z2 = [elem.exponentiate_by(self.k2) for elem in Z_from_p1]
        random.shuffle(Z2)
        # For each own (w,t), compute H(w)^{k2} and encrypt t with Paillier
        pairs = []
        for (w, t) in self.pairs:
            s = id_to_scalar(w, seed=self.seed)
            elem = ScalarGroupElem(s).exponentiate_by(self.k2)  # H(w)^{k2}
            enc_t = self.paillier_pub.encrypt(t)
            pairs.append((elem, enc_t))
        random.shuffle(pairs)
        return Z2, pairs

    def round3_receive_and_decrypt(self, enc_sum):
        # decrypt sum
        s = self.paillier_priv.decrypt(enc_sum)
        return s

# ---------------------------
# Demo run (single-machine simulate network)
# ---------------------------

def demo():
    # create sample ids
    seed = b"session-seed-123"  # common random seed as suggested in paper
    V = [b"userA", b"userB", b"userC", b"userD"]   # P1 identifiers
    W_pairs = [(b"userX", 10), (b"userB", 7), (b"userC", 5), (b"userY", 3)]  # P2 has B and C in intersection

    P1 = Party1(V, seed=seed)
    P2 = Party2(W_pairs, seed=seed)

    # P2 generates Paillier keys and shares public key with P1
    paillier_pub = P2.setup_paillier(keysize=1024)

    # Round 1: P1 -> P2 : send {H(vi)^{k1}}
    msg1 = P1.round1_send()

    # Round 2: P2 exponentiates and returns Z; also send {(H(wj)^{k2}, AEnc(tj))}
    Z2, pairs = P2.round2_receive_Z_and_respond(msg1)

    # Round 3: P1 exponentiates received H(wj)^{k2} by k1, finds intersection and homomorphically sums AEnc(tj)
    refreshed_ct, intersection_size = P1.round3_receive_and_compute(pairs, paillier_pub)

    # P1 sends refreshed_ct to P2 who decrypts
    S = P2.round3_receive_and_decrypt(refreshed_ct)
    print("Intersection size (P1 observed):", intersection_size)
    print("Intersection sum (P2 decrypted):", S)
    # For verification: real sum over common IDs
    expected = sum(t for (w,t) in W_pairs if w in V)
    print("Expected sum:", expected)

if __name__ == "__main__":
    demo()
