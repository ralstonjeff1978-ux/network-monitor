import os
import sys

# Make the project importable (modules/, config.py) when running pytest.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
