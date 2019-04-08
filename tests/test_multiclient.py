import os
import unittest
from nipsi.multiclient import BloomFilter, Cardinality, CardinalityEfficient

def generate_set(count):
    return {os.urandom(10)} | {os.urandom(20) for _ in range(count-1)}

class BloomFilterTestCase(unittest.TestCase):
    def setUp(self):
        self.bf = BloomFilter(64, 8)
        self.set = generate_set(5)

        for elem in self.set:
            self.bf.add(elem)

    def test_parameters(self):
        m, k = BloomFilter.determine_parameters(max_elements=1000, error_rate=0.001)
        self.assertEqual(m, 14378)
        self.assertEqual(k, 10)

    def test_contains(self):
        for elem in self.set:
            self.assertIn(elem, self.bf)

class CardinalityTestCase(unittest.TestCase):
    def setUp(self):
        self.scheme = Cardinality()
        self.scheme.client_count = 5
        self.shared_elements = generate_set(3)
        self.sets = [generate_set(7) for _ in range(self.scheme.client_count)]

    def test_correctness(self):
        usks = self.scheme.setup(128, self.scheme.client_count)
        gid = (1).to_bytes(16, 'big')
        pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        ct_sets = {frozenset(self.scheme.encrypt(usks[i], gid, pt_sets[i]))
                for i in range(self.scheme.client_count)}

        pt_cardinality = len(pt_sets[0].intersection(*pt_sets))
        ct_cardinality = self.scheme.eval(ct_sets)

        self.assertEqual(pt_cardinality, ct_cardinality)

class CardinalityEfficientTestCase(unittest.TestCase):
    def setUp(self):
        self.scheme = CardinalityEfficient()
        self.scheme.client_count = 5
        self.shared_elements = generate_set(3)
        self.sets = [generate_set(2) for _ in range(self.scheme.client_count)]

    def test_parameters(self):
        m, k = CardinalityEfficient.determine_parameters(max_elements=1000, error_rate=0.001)
        self.assertEqual(m, 14378)
        self.assertEqual(k, 10)

    def test_correctness(self):
        pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        set_sizes = len(pt_sets[0])
        m, k = CardinalityEfficient.determine_parameters(max_elements=set_sizes, error_rate=0.001)
        usks = self.scheme.setup(128, self.scheme.client_count, m, k)
        gid = (1).to_bytes(16, 'big')
        ct_sets = [self.scheme.encrypt(usks[i], gid, pt_sets[i])
                for i in range(self.scheme.client_count)]

        pt_cardinality = len(pt_sets[0].intersection(*pt_sets))
        ct_cardinality = self.scheme.eval(ct_sets)

        self.assertEqual(pt_cardinality, ct_cardinality)
