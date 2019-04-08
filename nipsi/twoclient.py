"""Module for Two-Client Set Intersection schemes

Copyright 2019 Tim R. van de Kamp, University of Twente
All rights reserved.
Use of this source code is governed by the MIT license that can be
found in the LICENSE file.

Package nipsi contains implementations of the proposed schemes in the
paper “Two-Client and Multi-client Functional Encryption for Set
Intersection.”"""
from nipsi import NonInteractiveSetIntersection

import os
import hashlib
from operator import itemgetter
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.ecgroup import ECGroup, G, ZR
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from itertools import islice

class Cardinality(NonInteractiveSetIntersection):
    """Two-Client Set Intersect Cardinality scheme"""
    client_count = 2

    def setup(self, secpar):
        """Generate the clients' keys"""
        key = os.urandom(secpar // 8)
        return (key, key)

    def _prf(self, cipher, pt):
        """PRF mapping pt to bytes"""
        padding_len = 16 - (len(pt) % 16)
        pt = pt + b'\0' * padding_len

        encryptor = cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    def encrypt(self, usk, gid, pt_set):
        """Encrypt a plaintext set under a gid using usk
        
        Returns a set of ciphertexts."""
        iv = gid
        cipher = Cipher(algorithms.AES(usk), modes.CBC(iv), backend=default_backend())

        ct_set = {self._prf(cipher, pt) for pt in pt_set}
        return ct_set

    def eval(self, ct_sets):
        """Evaluates the ciphertexts for determining the cardinality of the set intersection
        
        Expects two sets of ciphertexts."""
        return len(ct_sets[0] & ct_sets[1])

class Intersection(NonInteractiveSetIntersection):
    """Two-Client Set Intersect scheme"""
    client_count = 2

    def __init__(self, curve=prime256v1):
        super().__init__()
        self.group = ECGroup(curve)
        self.g = self.group.random(G)

    def setup(self, secpar):
        """Generate the clients' keys"""
        self.secpar = secpar

        sigma = self.group.random(ZR)
        msk = os.urandom(secpar // 8)

        return ((msk, sigma), (msk, 1-sigma))

    def _phi(self, cipher, pt):
        """PRF mapping pt to a group element"""
        padding_len = 16 - (len(pt) % 16)
        pt = pt + b'\0' * padding_len

        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()

        exponent = int.from_bytes(ct, 'big') % self.group.order()
        return self.g ** exponent

    def _H(self, g):
        """Mapping of g to bytes
        
        Can be used to map a group element g to an AE key."""
        prefix = b'\x00'
        hashable = prefix + self.group.serialize(g)
        h = hashlib.sha256(hashable).digest()
        return h[:16]

    def _H_bytes(self, g):
        """Mapping of g to bytes
        
        Can be used to map a group element g to an AE nonce."""
        prefix = b'\x01'
        hashable = prefix + self.group.serialize(g)
        h = hashlib.sha256(hashable).digest()

        return h

    def encrypt(self, usk, gid, pt_set):
        """Encrypt a plaintext set under a gid using usk

        Returns a dict of ciphertexts."""
        msk, sigma = usk

        iv = gid
        cipher = Cipher(algorithms.AES(msk), modes.CBC(iv), backend=default_backend())

        ct_dict = {}
        for pt in pt_set:
            k = self._phi(cipher, pt)
            ct1 = self.group.serialize(k**sigma)

            # use deterministic authenticated encryption
            ae_key = self._H(k)
            ae_nonce = self._H_bytes(k)[:12]
            ae = AESGCM(ae_key)
            ct2 = (ae_nonce, ae.encrypt(ae_nonce, pt, None))

            ct_dict[ae_key] = (ct1, ct2)

        return ct_dict

    def eval(self, ct_sets):
        """Evaluates the ciphertexts for determining the cardinality of the set intersection
        
        Expects two dicts of ciphertexts."""
        pt_intersection = set()
        ct_intersection = ct_sets[0].keys() & ct_sets[1].keys()

        for k in ct_intersection:
            g1 = self.group.deserialize(ct_sets[0][k][0])
            g2 = self.group.deserialize(ct_sets[1][k][0])
            key = g1 * g2

            # decrypt using ct_sets[0]
            ae_nonce, ct = ct_sets[0][k][1]
            ae_key = self._H(key)
            ae = AESGCM(ae_key)
            pt = ae.decrypt(ae_nonce, ct, None)

            pt_intersection.add(pt)

        return pt_intersection

class Threshold(Intersection):
    """Two-Client Threshold Set Intersect scheme"""
    client_count = 2

    def setup(self, secpar, threshold):
        """Generate the clients' keys"""
        self.secpar = secpar
        self.threshold = threshold
        self.ff_order = int(self.group.order()) - 1

        sigma = self.group.random(ZR)
        rho1 = int(self.group.random(ZR))
        rho2 = (1 - rho1) % self.ff_order
        sk1, sk2, sk3 = [os.urandom(secpar // 8) for _ in range(3)]

        return ((sk1, sk2, sk3, sigma, rho1), (sk1, sk2, sk3, 1-sigma, rho2))

    def _psi(self, cipher, pt):
        """PRF mapping pt to a finite field element"""
        padding_len = 16 - (len(pt) % 16)
        pt = pt + b'\0' * padding_len

        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()

        return self.group.init(ZR, int.from_bytes(ct, 'big'))

    def encrypt(self, usk, gid, pt_set):
        """Encrypt a plaintext set under a gid using usk

        Returns a dict of ciphertexts."""
        sk1, sk2, sk3, sigma, rho = usk

        iv = gid
        phi = Cipher(algorithms.AES(sk1), modes.CBC(iv), backend=default_backend())
        psi1 = Cipher(algorithms.AES(sk2), modes.CBC(iv), backend=default_backend())
        psi2 = Cipher(algorithms.AES(sk3), modes.CBC(iv), backend=default_backend())

        cs = [self._psi(psi2, i.to_bytes(16, 'big')) for i in range(self.threshold)]
        def f(x):
            """Shamir secret sharing polynomial"""
            return sum([c * x**i for i, c in enumerate(cs)])

        ae1_key = self._H(cs[0])
        ae1_nonce = os.urandom(12)
        ae1 = AESGCM(ae1_key)
        ct_dict = {}
        for pt in pt_set:
            k1 = self._phi(phi, pt)
            k2 = self._psi(psi1, pt)

            ct1 = self.group.serialize(k2)

            ct2 = self.group.serialize(f(k2) ** rho)

            k1_sigma = self.group.serialize(k1 ** sigma)
            ct3 = (ae1_nonce, ae1.encrypt(ae1_nonce, k1_sigma, None))

            ae2_key = self._H(k1)
            ae2_nonce = os.urandom(12)
            ae2 = AESGCM(ae2_key)
            ct4 = (ae2_nonce, ae2.encrypt(ae2_nonce, pt, None))

            ct_dict[ct1] = (ct2, ct3, ct4)

        return ct_dict

    def eval(self, ct_sets):
        """Evaluates the ciphertexts for determining the cardinality of the set intersection
        
        Expects two dicts of ciphertexts."""
        cardinality = 0
        ct_intersection = ct_sets[0].keys() & ct_sets[1].keys()
        pt_intersection = set()

        cardinality = len(ct_intersection)
        if cardinality >= self.threshold:
            # we can determine the plaintext of the intersection
            def delta(S, i):
                prod = 1
                for j in S:
                    if i == j:
                        continue
                    prod *= j * (j - i)**(-1)

                return prod

            # first, recover co = f(0)
            xs, ys = [], []
            for k in islice(ct_intersection, self.threshold):
                xs.append(self.group.deserialize(k))
                ys.append(self.group.deserialize(ct_sets[0][k][0]) * self.group.deserialize(ct_sets[1][k][0]))
            c0 = sum([y * delta(xs, x) for x, y in zip(xs, ys)])

            # now decrypt the intersection
            ae1_key = self._H(c0)
            ae1 = AESGCM(ae1_key)
            for k in ct_intersection:
                _, (ct1_k1_nonce, ct1_k1_sigma), (ct1_ae_nonce, ct1_ae_ct) = ct_sets[0][k]
                _, (ct2_k1_nonce, ct2_k1_sigma), _ = ct_sets[1][k]

                # recover k1
                pt1_k1_sigma = ae1.decrypt(ct1_k1_nonce, ct1_k1_sigma, None)
                pt2_k1_sigma = ae1.decrypt(ct2_k1_nonce, ct2_k1_sigma, None)
                k1 = self.group.deserialize(pt1_k1_sigma) * self.group.deserialize(pt2_k1_sigma)

                # decrypt ct4
                ae2_key = self._H(k1)
                ae2 = AESGCM(ae2_key)
                pt = ae2.decrypt(ct1_ae_nonce, ct1_ae_ct, None)
                pt_intersection.add(pt)

        return cardinality, pt_intersection
