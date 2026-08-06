import sys
import pathlib

# Make the project root importable so `import detector` works under pytest.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
