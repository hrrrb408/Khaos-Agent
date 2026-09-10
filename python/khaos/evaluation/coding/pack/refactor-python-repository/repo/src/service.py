from .repository import Repository


def fetch(repo: Repository, key):
    return repo.get(key)
