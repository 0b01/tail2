import numpy as np


def foo():
    data = np.random.gamma(2, 3, size=10000000)
    data.sort()
    print(data.mean())


def bar():
    foo()


def baz():
    foo()
    bar()

input()
baz()