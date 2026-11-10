"""
EvilTwinGuard test suite.

Run all tests:        python -m unittest discover -s tests -v
Run one group:        python -m unittest tests.test_blackbox -v
With coverage:        python -m coverage run -m unittest discover -s tests
                      python -m coverage report

Every test uses a throw-away SQLite database (DATABASE_PATH is pointed at a
temporary directory before the application is imported), so running the
suite never touches evil_twin_detector.db.
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix='etg-tests-')
os.environ['DATABASE_PATH'] = os.path.join(_TMP, 'test.db')
