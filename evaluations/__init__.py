class EvaluationCase:
    def __init__(self):
        self.scenarios = []

        self.repeat = 3
        self.number = 1000000

    def setUp(self, scenario=None):
        raise NotImplementedError
