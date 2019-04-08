"""Evaluate main program

Based on unittest"""

import csv
import importlib
import inspect
import os
import pkgutil
import timeit

from .__init__ import EvaluationCase
from operator import itemgetter

class EvaluateProgram(object):
    def __init__(self):
        evaluations_dir = os.path.abspath('evaluations')
        self.discover(evaluations_dir)

        self.results_dir = os.path.join(evaluations_dir, 'results')
        try:
            os.mkdir(self.results_dir)
        except FileExistsError:
            pass

        # output file configuration
        self.file_extension = '.dat'
        self.col_sep = ';'
        self.format_str = '{:f}'

        self.run()

    def discover(self, evaluations_dir):
        def all_subclasses(cls):
            return set(cls.__subclasses__()).union([s
                for c in cls.__subclasses__() for s in all_subclasses(c)])

        # import all submodules
        for (module_loader, name, ispkg) in pkgutil.iter_modules([evaluations_dir]):
            if name != '__main__':
                importlib.import_module('.' + name, __package__)

        self.evaluation_classes = {cls.__name__: cls
                for cls in all_subclasses(EvaluationCase)
                if cls.__name__.endswith('Evaluation')}

    def run(self):
        for class_name, evaluation_class in self.evaluation_classes.items():
            print(class_name, len(class_name)*'=', sep='\n')
            evaluation = evaluation_class()

            methods = [(method_name, method)
                    for method_name, method in inspect.getmembers(evaluation, predicate=inspect.ismethod)
                    if method_name.startswith('evaluate')]
            methods.sort()

            if len(methods) == 0 or len(evaluation.scenarios) == 0:
                continue
            
            evaluations = []
            for scenario in evaluation.scenarios:
                evaluation.setUp(scenario)

                result = {'scenario': scenario}
                for method_name, method in methods:
                    print('{}.{} (scenario {})...'.format(class_name, method_name, scenario), end=' ', flush=True)

                    # use the evaluation parameters
                    evaluation.setup="pass"
                    parameters = inspect.signature(method).parameters
                    for name, value in parameters.items():
                        if name in {'setup'}:
                            setattr(evaluation, name, value.default)

                    timer = timeit.Timer(method, setup=evaluation.setup, globals={'evaluation': evaluation})
                    timings = [timing / evaluation.number
                            for timing in timer.repeat(evaluation.repeat, evaluation.number)]

                    # Since we’re testing with random data, we ignore the advise from
                    # https://docs.python.org/library/timeit.html#timeit.Timer.repeat
                    # and compute the sample mean and sample variance.
                    timings_sum = sum(timings)
                    mean = timings_sum / len(timings)

                    # compute the sample variance as an unbiased estimator
                    # 1 / (n - 1) sum [ (x_i - mean)^2 ]
                    squared_timings_sum = sum([x**2 for x in timings])
                    variance = (squared_timings_sum - timings_sum**2 / len(timings)) / (len(timings) - 1)

                    name = method_name[len('evaluate'):].strip('_')
                    result[name + '_mean'] = self.format_str.format(mean)
                    result[name + '_var'] = self.format_str.format(variance)
                    print('done (mean: {:f} sec)'.format(mean))

                evaluations.append(result)

            # create evaluation files
            filename = os.path.join(self.results_dir, class_name + self.file_extension)
            with open(filename, 'w', newline='') as f:
                fieldnames = list(evaluations[0].keys())
                fieldnames.remove('scenario')
                fieldnames.sort()
                fieldnames = ['scenario'] + fieldnames
                writer = csv.DictWriter(f, fieldnames=fieldnames)

                writer.writeheader()
                for evaluation in evaluations:
                    writer.writerow(evaluation)

main = EvaluateProgram
