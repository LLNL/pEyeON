from .cli import main
from .observe import observe

# from .parse import *


def dummy_calls():
    main()
    x = observe.Observe("something.exe")
    return x
