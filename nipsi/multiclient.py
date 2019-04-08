"""Module for Multi-client Set Intersection schemes

Copyright 2019 Tim R. van de Kamp, University of Twente
All rights reserved.
Use of this source code is governed by the MIT license that can be
found in the LICENSE file.

Package nipsi contains implementations of the proposed schemes in the
paper “Two-Client and Multi-client Functional Encryption for Set
Intersection.”"""
from nipsi import NonInteractiveSetIntersection

import mmh3
import os
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.ecgroup import ECGroup, G, ZR
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from functools import reduce
from itertools import product
from math import log, log2

class BloomFilter:
    class BitString:
        bit_weights = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8]

        def __init__(self, l):
            self.l = l
            self._bs = bytearray((l + 7) // 8)

        def __repr__(self):
            number = int.from_bytes(self._bs, 'little')
            return '{number:0{width}b}'.format(number=number, width=self.l)

        def __getitem__(self, key):
            byte_index = key // 8
            byte = self._bs[byte_index]

            shift = key % 8
            bit_index = 1 << shift

            return (byte & bit_index) >> shift

        def __setitem__(self, key, value):
            assert value == 0 or value == 1, '{} is not a bit'.format(value)

            byte_index = key // 8
            byte = self._bs[byte_index]

            shift = key % 8
            bit_index = 1 << shift

            self._bs[byte_index] |= bit_index

        def __and__(self, other):
            assert self.l == other.l

            bs = BloomFilter.BitString(self.l)
            for i in range(self.l // 8):
                bs._bs[i] = self._bs[i] & other._bs[i]
            return bs

        def __or__(self, other):
            assert self.l == other.l

            bs = BloomFilter.BitString(self.l)
            for i in range(self.l // 8):
                bs._bs[i] = self._bs[i] | other._bs[i]
            return bs

        def weight(self):
            return sum([self.bit_weights[byte] for byte in self._bs])

    @staticmethod
    def determine_parameters(max_elements, error_rate=0.001):
        """Determine the Bloom filter parameters"""
        n = max_elements
        p = error_rate
        m = round(-(n * log(p)) / pow(log(2), 2))
        k = round(-log2(p))

        return m, k

    def __init__(self, m, k):
        """Create an empty Bloom filter
        
        m - bit string length in bits
        k - number of used hash function"""
        self.m = m
        self.k = k

        if m.bit_length() > 32:
            H = mmh3.hash128
        else:
            H = mmh3.hash

        self.bs = self.BitString(m)
        self._h = [(lambda x: (lambda y: H(x + y) % m))(i.to_bytes(k.bit_length(), 'big'))
                for i in range(k)]

    def __repr__(self):
        return repr(self.bs)

    def __contains__(self, item):
        return all(self.bs[h(item)] for h in self._h)

    def __and__(self, other):
        return self.intersection(other)

    def __or__(self, other):
        return self.union(other)

    def empty(self):
        bf = BloomFilter(self.m, self.k)
        bf._h = self._h
        return bf

    def add(self, elem):
        for h in self._h:
            self.bs[h(elem)] = 1

    def union(self, other):
        bf = self.empty()
        bf.bs = self.bs | other.bs
        return bf

    def intersection(self, other):
        bf = self.empty()
        bf.bs = self.bs & other.bs
        return bf

    def weight(self):
        return self.bs.weight()

class Cardinality(NonInteractiveSetIntersection):
    """Multi-client Set Intersect Cardinality scheme"""
    def __init__(self, curve=prime256v1):
        super().__init__()
        self.group = ECGroup(curve)
        self.g = self.group.random(G)

    def setup(self, secpar, client_count):
        """Generate the clients' keys"""
        self.client_count = client_count
        usks = [self.group.random(ZR) for _ in range(client_count-1)]
        usks.append(-sum(usks))
        return usks

    def encrypt(self, usk, gid, pt_set):
        """Encrypt a plaintext set under a gid using usk
        
        Returns a set of ciphertexts."""
        H = self.group.hash
        ct_set = {self.group.serialize(H(gid + pt, G)**usk) for pt in pt_set}

        return ct_set

    def eval(self, ct_sets):
        """Evaluates the ciphertexts for determining the cardinality of the set intersection
        
        Expects a list or set of ciphertexts."""
        one = self.g ** 0
        def intersection_count(ct_sets, product=one):
            # Recursive function call to compute the Cartesian product
            # Features:
            # 1) remember the partial product;
            # 2) avoid computations with elements for which we know that they
            #    belong to the intersection.
            ct_set, ct_sets = set(ct_sets[-1]), ct_sets[:-1]
            count = 0
            if ct_sets == []:
                for ct_str in ct_set:
                    ct = self.group.deserialize(ct_str)

                    if product * ct == one:
                        ct_set.remove(ct_str)
                        count = 1
                        break
            else:
                for ct_str in ct_set.copy():
                    ct = self.group.deserialize(ct_str)

                    found, ct_sets = intersection_count(ct_sets, product * ct)
                    if found == 1:
                        ct_set.remove(ct_str)
                        count += 1
                        # Note that we cannot break here: if we would break
                        # here, we might skip other ct's that are in the set.

            ct_sets.append(ct_set)
            return (count, ct_sets)

        cardinality, _ = intersection_count(list(ct_sets))
        return cardinality

class CardinalityEfficient(Cardinality):
    @staticmethod
    def determine_parameters(max_elements, error_rate=0.001):
        """Determine the Bloom filter parameters for the worst case set intersection"""
        # The worst case Bloom filter resulting from the set intersection is the
        # same as a Bloom filter with the same number of elements inserted minus
        # the expected set intersection size.
        return BloomFilter.determine_parameters(max_elements, error_rate)

    def setup(self, secpar, client_count, m, k):
        """Generate the clients' keys"""
        self.m = m
        self.k = k

        phi_key = os.urandom(secpar // 8)

        cs = [0] + [self.group.random(ZR) for i in range(self.client_count)]
        def f(x):
            """Shamir secret sharing polynomial"""
            return sum([c * x**i for i, c in enumerate(cs)])

        usks = [(phi_key, f(i), f(self.client_count + i))
                for i in range(1, 1 + self.client_count)]

        return usks

    def _prf(self, cipher, pt):
        """PRF mapping pt to bytes"""
        padding_len = 16 - (len(pt) % 16)
        pt = pt + b'\0' * padding_len

        encryptor = cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    def encrypt(self, usk, gid, pt_set):
        """Encrypt a plaintext set under a gid using usk
        
        Returns a tuple of ciphertexts."""
        phi_key, fi, fni = usk
        H = self.group.hash

        bf_set = BloomFilter(self.m, self.k)

        iv = gid
        cipher = Cipher(algorithms.AES(phi_key), modes.CBC(iv), backend=default_backend())
        ct_elements = []
        for pt in pt_set:
            ct = self._prf(cipher, pt)
            bf_set.add(ct)

            # encrypt all individual set elements
            bf = BloomFilter(self.m, self.k)
            bf.add(ct)
            t = bf.weight()
            ct_element = []
            for i in range(bf.m):
                ct = H(i.to_bytes(self.k.bit_length(), 'big') + gid, G) ** fni
                gr = self.group.random(G)
                if bf.bs[i] == 0:
                    grho = self.group.random(G)
                else:
                    grho = gr ** t
                ct *= grho
                ct_element.append((ct, gr))
            ct_elements.append(ct_element)

        # encrypt the Bloom filter for complete set
        ct_bf_set = []
        for i in range(bf_set.m):
            ct = H(i.to_bytes(self.k.bit_length(), 'big') + gid, G) ** fi
            if bf_set.bs[i] == 0:
                ct *= self.group.random(G)
            ct_bf_set.append(ct)

        return (ct_bf_set, ct_elements)

    def eval(self, ct_sets):
        """Evaluates the ciphertexts for determining the cardinality of the set intersection
        
        Expects lists containing ciphertexts."""
        cardinality = 0

        def delta(S, i):
            """Lagrange interpolation helper"""
            prod = 1
            for j in S:
                if i == j:
                    continue
                prod *= j * (j - i)**(-1)

            return prod

        smallest_set_index = 0
        smallest_set_size = len(ct_sets[0][1])
        for i in range(1, len(ct_sets)):
            if len(ct_sets[i][1]) < smallest_set_size:
                smallest_set_index = i
                smallest_set_size = len(ct_sets[i][1])

        gamma = smallest_set_index + 1
        S = [self.group.init(ZR, i) for i in range(1, 1 + self.client_count)]
        S += [ self.group.init(ZR, self.client_count + gamma) ]

        a_list = []
        one = self.g ** 0
        for ell in range(self.m):
            a = one
            for i, ct_set in enumerate(ct_sets):
                ct_bf_set = ct_set[0]
                ct_i = self.group.init(ZR, i + 1)
                a *= ct_bf_set[ell] ** delta(S, ct_i)

            a_list.append(a)

        _, ct_elements = ct_sets[smallest_set_index]

        Delta = delta(S, self.client_count + gamma)
        for ct_element in ct_elements:
            t = None
            identical_count = 0

            for ell in range(self.m):
                lhs = ct_element[ell][0] ** Delta * a_list[ell]
                if t is None:
                    # find the candidate t; one we found t it is with
                    # overwhelming probablily the correct one, so we don't check
                    # for the other ell for different values for t.
                    for i in range(self.k, 0, -1):
                        rhs = ct_element[ell][1] ** (Delta * i)
                        if lhs == rhs:
                            t = i
                            identical_count = 1
                            break
                else:
                    rhs = ct_element[ell][1] ** (Delta * t)
                    if lhs == rhs:
                        identical_count += 1
                        if t == identical_count:
                            cardinality += 1
                            break

        return cardinality
