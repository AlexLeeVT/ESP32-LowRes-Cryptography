#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

if __name__ == "__main__":
    # get environment paths
    idf_py = Path(os.environ.get("IDF_PATH")) / "tools" / "idf.py" # get esp-idf tool paths
    python_env = Path(os.environ.get("IDF_PYTHON_ENV_PATH")) / "bin" / "python" # get esp-idf special python path (to run idf.py)

    subprocess.run([str(python_env), str(idf_py), "build"])