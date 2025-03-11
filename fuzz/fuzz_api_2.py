import atheris
import sys
from calculator.src import API_2_good

def TestOneInput(data):
    try:
        API_2_good(int(data), float(data), str(data))
    except:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
