from .__init__ import EvaluationCase
from nipsi import NonInteractiveSetIntersection
import os

def generate_set(count):
    return {os.urandom(16) for _ in range(count)}

class BaseEvaluationCase(EvaluationCase):
    def __init__(self):
        super().__init__()
        self.repeat = 5
        self.number = 20

        self.scheme = NonInteractiveSetIntersection()

    def setUp(self, scenario, shared=None):
        self.secpar = 128

        if shared is None:
            # the sets have 10% of their elements in common
            shared_elements = scenario // 10
        else:
            shared_elements = shared

        self.shared_elements = generate_set(shared_elements)
        self.sets = [generate_set(scenario - shared_elements)
                for _ in range(self.scheme.client_count)]

    def default_cases(self):
        self.gid = (1).to_bytes(16, 'big')
        self.pt_sets = [self.shared_elements | self.sets[i]
                for i in range(self.scheme.client_count)]
        self.ct_sets = [self.scheme.encrypt(self.usks[i], self.gid, self.pt_sets[i])
                for i in range(self.scheme.client_count)]

    def evaluate_encrypt(self):
        ct_sets = [self.scheme.encrypt(self.usks[i], self.gid, self.pt_sets[i])
                for i in range(self.scheme.client_count)]

    def evaluate_eval(self):
        result = self.scheme.eval(self.ct_sets)

class TCEvaluationCase(BaseEvaluationCase):
    def __init__(self):
        super().__init__()

        self.scenarios = [
                10, 20, 30, 40, 50,
                100, 150, 200, 250, 500,
                1000, 5000,
                10000, 50000,
                100000,
                ]

class MCEvaluationCase(BaseEvaluationCase):
    def __init__(self):
        super().__init__()
        self.repeat = 3
        self.number = 5
        self.scenarios = [
                10, 20, 30, 40, 50, 60, 70, 80, 90,
                100, 110, 120, 130, 140, 150, 160, 170, 180, 190,
                200, 250,
                ]
