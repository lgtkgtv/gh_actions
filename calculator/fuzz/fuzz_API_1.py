import atheris
import sys
from calculator import API_1_good, API_1_bad

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    x = fdp.ConsumeInt(4)
    y = fdp.ConsumeInt(4)
    
    try:
        API_1_good(x, y)
        API_1_bad(x, y)
    except Exception as e:
        print(f"Exception caught in API_1: {e}")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
