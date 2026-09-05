from .index import PrefixIndex


class SearchService:
    def __init__(self):
        self.index = PrefixIndex()
