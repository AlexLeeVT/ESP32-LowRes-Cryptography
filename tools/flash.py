#!/usr/bin/env python3
import os, sys, getopt
import subprocess
from pathlib import Path

args = sys.argv[1:]
options = "p:"
long_options = ["port"]

if __name__ == "__main__":
    # parse cli arguments
    try:
        arguments, values = getopt.getopt(args, options, long_options)

        if not any(arg in ("-p", "--port") for arg, val in arguments):
            raise SystemExit("No port listed. Try flash.py -p [device].")

        for currentArg, currentVal in arguments:
            if currentArg in ("-p", "--port"):
                device = str(currentVal)
    except getopt.error as err:
        raise SystemExit(str(err))
    
    # get environment paths
    idf_py = Path(os.environ.get("IDF_PATH")) / "tools" / "idf.py" # get esp-idf tool paths
    python_env = Path(os.environ.get("IDF_PYTHON_ENV_PATH")) / "bin" / "python" # get esp-idf special python path (to run idf.py)

    # flash the device
    subprocess.run([str(python_env), str(idf_py), "-p", device, "flash"], check=True)