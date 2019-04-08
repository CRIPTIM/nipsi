import os
import unittest
from nipsi.twoclient import Cardinality, Intersection, Threshold

def generate_set(count):
    return {os.urandom(10)} | {os.urandom(20) for _ in range(count-1)}

class CardinalityTestCase(unittest.TestCase):
    def setUp(self):
        self.scheme = Cardinality()
        self.shared_elements = generate_set(50)
        self.sets = [generate_set(250) for _ in range(self.scheme.client_count)]

    def test_correctness(self):
        usks = self.scheme.setup(128)
        gid = b'identifier'.rjust(16, b'\0')
        pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        ct_sets = [self.scheme.encrypt(usks[i], gid, pt_sets[i])
                for i in range(self.scheme.client_count)]

        pt_cardinality = len(pt_sets[0] & pt_sets[1])
        ct_cardinality = self.scheme.eval(ct_sets)

        self.assertEqual(pt_cardinality, ct_cardinality)

class IntersectionTestCase(unittest.TestCase):
    def setUp(self):
        self.scheme = Intersection()
        self.shared_elements = generate_set(50)
        self.sets = [generate_set(250) for _ in range(self.scheme.client_count)]

    def test_correctness(self):
        usks = self.scheme.setup(128)
        gid = b'identifier'.rjust(16, b'\0')
        pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        ct_sets = [self.scheme.encrypt(usks[i], gid, pt_sets[i])
                for i in range(self.scheme.client_count)]

        pt_intersection = pt_sets[0] & pt_sets[1]
        ct_intersection = self.scheme.eval(ct_sets)

        self.assertEqual(pt_intersection, ct_intersection)

class ThresholdTestCase(unittest.TestCase):
    def setUp(self):
        self.scheme = Threshold()
        self.shared_elements = generate_set(30)
        self.sets = [generate_set(270) for _ in range(self.scheme.client_count)]

    def test_cardinality(self):
        usks = self.scheme.setup(128, 50)
        gid = b'identifier'.rjust(16, b'\0')
        pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        ct_sets = [self.scheme.encrypt(usks[i], gid, pt_sets[i])
                for i in range(self.scheme.client_count)]

        pt_cardinality = len(pt_sets[0] & pt_sets[1])
        self.assertLess(pt_cardinality, self.scheme.threshold, msg="failure in test case")

        ct_cardinality, ct_intersection = self.scheme.eval(ct_sets)
        self.assertEqual(pt_cardinality, ct_cardinality)

    def test_intersection(self):
        usks = self.scheme.setup(128, 25)
        gid = b'identifier'.rjust(16, b'\0')
        pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        ct_sets = [self.scheme.encrypt(usks[i], gid, pt_sets[i])
                for i in range(self.scheme.client_count)]

        pt_cardinality, pt_intersection = len(pt_sets[0] & pt_sets[1]), pt_sets[0] & pt_sets[1]
        ct_cardinality, ct_intersection = self.scheme.eval(ct_sets)

        self.assertEqual(pt_cardinality, ct_cardinality)
        self.assertEqual(pt_intersection, ct_intersection)
