"""Desktop GUI launcher. Run:  python run_gui.py"""
import pathlib
import sys

# Make the project root importable so `detector` and `gui` packages resolve.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

try:
    from gui.app import main
except ModuleNotFoundError as e:
    if "customtkinter" in str(e):
        print("customtkinter kurulu degil. Kurmak icin:\n    pip install customtkinter")
        raise SystemExit(1)
    raise

if __name__ == "__main__":
    main()
