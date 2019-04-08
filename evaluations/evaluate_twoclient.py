from .config import TCEvaluationCase
from nipsi.twoclient import Cardinality, Intersection, Threshold

class TCCardinalityEvaluation(TCEvaluationCase):
    def __init__(self):
        super().__init__()
        self.scenarios = [
                10, 20, 30, 40, 50,
                100, 200, 300, 400, 500,
                1000, 2000, 3000, 4000, 5000,
                10000, 20000, 30000, 40000, 50000,
                100000,
                ]

    def setUp(self, scenario):
        self.scheme = Cardinality()
        super().setUp(scenario)
        self.usks = self.scheme.setup(self.secpar)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar)

class TCIntersectionEvaluation(TCEvaluationCase):
    def setUp(self, scenario):
        self.scheme = Intersection()
        super().setUp(scenario)
        self.usks = self.scheme.setup(self.secpar)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar)

class TCThresholdCardinalityEvaluation(TCEvaluationCase):
    def setUp(self, scenario):
        self.scheme = Threshold()
        super().setUp(scenario, shared=0)

        self.usks = self.scheme.setup(self.secpar, 2)
        self.default_cases()

    def evaluate_encrypt(self):
        # we evaluate this in TCThresholdIntersectionEvaluation
        pass

class TCThresholdIntersectionEvaluation(TCEvaluationCase):
    def setUp(self, scenario):
        self.scheme = Threshold()
        super().setUp(scenario)

        self.usks = self.scheme.setup(self.secpar, 1)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar, 5)
