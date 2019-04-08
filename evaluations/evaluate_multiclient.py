from .config import MCEvaluationCase
from nipsi.multiclient import Cardinality, CardinalityEfficient

class MCCardinality3Evaluation(MCEvaluationCase):
    def setUp(self, scenario):
        self.scheme = Cardinality()
        self.scheme.client_count = 3
        super().setUp(scenario)

        self.usks = self.scheme.setup(self.secpar, self.scheme.client_count)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar, self.scheme.client_count)

class MCCardinality5Evaluation(MCEvaluationCase):
    def __init__(self):
        super().__init__()
        self.scenarios = [5, 10, 20, 30, 40]

    def setUp(self, scenario):
        self.scheme = Cardinality()
        self.scheme.client_count = 5
        super().setUp(scenario)

        self.usks = self.scheme.setup(self.secpar, self.scheme.client_count)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar, self.scheme.client_count)

class MCCardinalityEfficient3Evaluation(MCEvaluationCase):
    def setUp(self, scenario):
        self.scheme = CardinalityEfficient()
        self.scheme.client_count = 3
        super().setUp(scenario)
        self.m, self.k = CardinalityEfficient.determine_parameters(max_elements=scenario, error_rate=0.001)

        self.usks = self.scheme.setup(self.secpar, self.scheme.client_count, self.m, self.k)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar, self.scheme.client_count, self.m, self.k)

    def evaluate_encrypt(self):
        # takes a long time and we don't care
        pass

class MCCardinalityEfficient5Evaluation(MCEvaluationCase):
    def setUp(self, scenario):
        self.scheme = CardinalityEfficient()
        self.scheme.client_count = 5
        super().setUp(scenario)
        self.m, self.k = CardinalityEfficient.determine_parameters(max_elements=scenario, error_rate=0.001)

        self.usks = self.scheme.setup(self.secpar, self.scheme.client_count, self.m, self.k)
        self.default_cases()

    def evaluate_setup(self):
        usks = self.scheme.setup(self.secpar, self.scheme.client_count, self.m, self.k)

    def evaluate_encrypt(self):
        # takes a long time and we don't care
        pass
