import os
from pathlib import Path

TESTS = Path(__file__).parent
TESTDATA = TESTS / "testdata"

os.environ['MYTHRIL_DIR'] = str(TESTS / "mythril_dir")
