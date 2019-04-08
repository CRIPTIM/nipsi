Implementation of several *Non-interactive Private Set Intersection* (NIPSI) schemes.

Installation
------------
Compile and install [Charm](https://github.com/JHUISI/charm).
Optionally, you may want to install Charm in a virtual environment.
If so, be sure to run `python setup.py install` from the same directory
as you ran `./configure.sh` and `make`.

```
python3 -m venv [VENV_PATH]
source [VENV_PATH]/bin/activate
cd [CHARM_PATH]
python setup.py install
```

Make sure to also install the other libraries
[cryptography](https://cryptography.io) and
[murmurhash3](https://github.com/veegee/mmh3).
```
pip install -r requirements.txt
```

Tests and Evaluation
--------------------
Running tests works with the standard `unittest`.
```
cd [NIPSI_PATH]
python3 -m unittest
```

The evaluations can be invoked in a similar manner.
```
cd [NIPSI_PATH]
python3 -m evaluations
```

Running the evaluations creates a `results` directory containing the
evaluation results for various functions and set sizes.

The evaluation results that are used in the paper can be found in the
directory `evaluations/published_results/`. These evaluations were run
on an Intel Core i5-4210U CPU @ 1.70GHz with 8 GB of RAM.

More information
----------------
These schemes are implementations for the paper “[Two-Client and
Multi-client Functional Encryption for Set
Intersection](https://timvandekamp.nl/paper/KSJ+19_acisp19.pdf)” by Van
de Kamp, Stritzl, Jonker, and Peter, presented at
[ACISP 2019](https://acisp19.canterbury.ac.nz/).
