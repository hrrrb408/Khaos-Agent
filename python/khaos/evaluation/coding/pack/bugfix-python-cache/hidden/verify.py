import runpy

Cache = runpy.run_path("src/cache.py")["Cache"]


cache = Cache()
cache.put("zero", 0)
cache.put("false", False)
cache.put("empty", "")

assert cache.get("zero", 99) == 0
assert cache.get("false", True) is False
assert cache.get("empty", "fallback") == ""
assert cache.get("missing", "fallback") == "fallback"
