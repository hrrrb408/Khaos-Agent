class Cache:
    def __init__(self, compute):
        self._values = {}
        self._compute = compute

    def get_or_compute(self, key):
        if key not in self._values:
            value = self._compute(key)
            self._values[key] = value
        return self._values[key]
