class PrefixIndex:
    def __init__(self):
        self._values = {}

    def add(self, key, value):
        self._values.setdefault(key, []).append(value)
