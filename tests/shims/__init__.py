"""Optional dependency shims for unittest-only test environments."""

from __future__ import annotations

import importlib
import math
import sys
import types


def _install_pytest_stub() -> None:
    if "pytest" in sys.modules:
        return
    try:
        importlib.import_module("pytest")
        return
    except ModuleNotFoundError:
        pass

    pytest = types.ModuleType("pytest")

    def fixture(func=None, *args, **kwargs):
        if func is None:
            return lambda f: f
        return func

    class _Approx:
        def __init__(self, expected, abs=None, rel=None):
            self.expected = expected
            self.abs = 1e-12 if abs is None and rel is None else abs
            self.rel = rel

        def __eq__(self, other):
            tolerance = self.abs
            if tolerance is None:
                tolerance = abs(self.expected) * (self.rel if self.rel is not None else 1e-6)
            return math.isclose(other, self.expected, abs_tol=tolerance, rel_tol=self.rel or 0.0)

    pytest.fixture = fixture
    pytest.approx = lambda expected, abs=None, rel=None: _Approx(expected, abs=abs, rel=rel)
    pytest.fail = lambda msg="pytest.fail() called": (_ for _ in ()).throw(AssertionError(msg))
    pytest.mark = types.SimpleNamespace(
        skip=lambda *a, **k: (lambda f: f),
        xfail=lambda *a, **k: (lambda f: f),
    )
    sys.modules["pytest"] = pytest


def _install_numpy_stub() -> None:
    if "numpy" in sys.modules:
        return
    try:
        importlib.import_module("numpy")
        return
    except ModuleNotFoundError:
        pass

    numpy = types.ModuleType("numpy")
    numpy.ndarray = list
    numpy.float32 = float
    numpy.float64 = float
    numpy.array = lambda values, dtype=None: list(values) if not isinstance(values, list) else values
    numpy.asarray = lambda values, dtype=None: list(values) if not isinstance(values, list) else values
    numpy.zeros = lambda n, dtype=None: [0.0] * int(n)
    numpy.mean = lambda values: (sum(values) / len(values)) if values else 0.0
    numpy.std = lambda values: 0.0
    numpy.sqrt = math.sqrt
    numpy.exp = math.exp
    numpy.log = lambda x: math.log(x) if x > 0 else 0.0
    numpy.log1p = math.log1p
    numpy.isnan = lambda x: x != x
    numpy.clip = lambda value, lo, hi: max(lo, min(value, hi))
    numpy.sort = lambda values: sorted(values)
    numpy.searchsorted = lambda arr, x, side="left": sum(
        1 for item in arr if item < x or (side == "right" and item <= x)
    )
    numpy.percentile = lambda values, pct: (
        0.0 if not values else sorted(values)[
            max(0, min(len(values) - 1, int(round((pct / 100.0) * (len(values) - 1)))))
        ]
    )
    sys.modules["numpy"] = numpy


def _install_joblib_stub() -> None:
    if "joblib" in sys.modules:
        return
    try:
        importlib.import_module("joblib")
        return
    except ModuleNotFoundError:
        pass

    joblib = types.ModuleType("joblib")
    joblib.dump = lambda obj, path: path
    joblib.load = lambda path: []
    sys.modules["joblib"] = joblib


def _install_sklearn_stub() -> None:
    if "sklearn" in sys.modules:
        return
    try:
        importlib.import_module("sklearn.ensemble")
        importlib.import_module("sklearn.decomposition")
        importlib.import_module("sklearn.preprocessing")
        return
    except ModuleNotFoundError:
        pass

    sklearn = types.ModuleType("sklearn")
    ensemble = types.ModuleType("sklearn.ensemble")
    decomposition = types.ModuleType("sklearn.decomposition")
    preprocessing = types.ModuleType("sklearn.preprocessing")

    class _BaseEstimator:
        def __init__(self, *args, **kwargs):
            pass

        def fit(self, *args, **kwargs):
            return self

        def partial_fit(self, *args, **kwargs):
            return self

        def transform(self, data):
            return data

        def inverse_transform(self, data):
            return data

        def decision_function(self, data):
            return [0.0 for _ in data] if isinstance(data, list) else [0.0]

        def predict(self, data):
            return [1 for _ in data] if isinstance(data, list) else [1]

    class IsolationForest(_BaseEstimator):
        pass

    class IncrementalPCA(_BaseEstimator):
        pass

    class StandardScaler(_BaseEstimator):
        pass

    ensemble.IsolationForest = IsolationForest
    decomposition.IncrementalPCA = IncrementalPCA
    preprocessing.StandardScaler = StandardScaler
    sklearn.ensemble = ensemble
    sklearn.decomposition = decomposition
    sklearn.preprocessing = preprocessing

    sys.modules["sklearn"] = sklearn
    sys.modules["sklearn.ensemble"] = ensemble
    sys.modules["sklearn.decomposition"] = decomposition
    sys.modules["sklearn.preprocessing"] = preprocessing


def activate_test_shims() -> None:
    _install_pytest_stub()
    _install_numpy_stub()
    _install_joblib_stub()
    _install_sklearn_stub()
