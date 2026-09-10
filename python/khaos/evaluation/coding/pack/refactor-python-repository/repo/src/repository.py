class Repository:
    def __init__(self, rows):
        self.rows = rows

    def get(self, key):
        return self.rows.get(key)
