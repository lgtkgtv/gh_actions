import atheris
import sys
from calculator import API_2_good, API_2_bad

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    x = fdp.ConsumeInt(4)
    y = fdp.ConsumeFloat()
    z = fdp.ConsumeString(4)
    
    try:
        API_2_good(x, y, z)
        API_2_bad(x, y, z)
    except Exception as e:
        print(f"Exception caught in API_2: {e}")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
