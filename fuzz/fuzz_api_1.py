import atheris
import sys
from calculator.src import API_1_good

def TestOneInput(data):
    try:
        API_1_good(int(data), int(data))
    except:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
