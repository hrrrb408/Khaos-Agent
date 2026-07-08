"""文件内容指纹缓存，避免重复注入未修改的文件。"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class FileFingerprintCache:
    """缓存文件内容 hash，检测文件是否在上次注入后发生变化。

    用途：coding 模式的 CodingContextBuilder 在每轮对话时收集相关文件，
    但大部分文件内容没有变化，不需要重新注入。通过 hash 比对跳过未变化的文件，
    节省 token 开销。
    """

    def __init__(self, max_entries: int = 500):
        self._cache: dict[str, str] = {}  # path -> content_hash
        self._max_entries = max_entries

    def _hash_content(self, content: str) -> str:
        """计算内容 hash。"""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get_hash(self, path: str) -> Optional[str]:
        """获取缓存的 hash，不存在返回 None。"""
        return self._cache.get(path)

    def is_changed(self, path: str, content: str) -> bool:
        """检查文件内容是否相对于缓存发生了变化。

        如果 path 不在缓存中（首次看到），返回 True（视为变化，需要注入）。
        """
        current_hash = self._hash_content(content)
        cached = self._cache.get(path)
        if cached is None:
            return True  # 首次看到
        return current_hash != cached

    def update(self, path: str, content: str) -> None:
        """更新文件 hash 缓存。"""
        if len(self._cache) >= self._max_entries:
            # 简单策略：清空一半最早的缓存（按插入序）。
            evict_count = max(1, self._max_entries // 2)
            for key in list(self._cache.keys())[:evict_count]:
                self._cache.pop(key, None)
            logger.debug(
                "fingerprint cache evicted %d entries (size=%d)",
                evict_count,
                len(self._cache),
            )
        self._cache[path] = self._hash_content(content)

    def invalidate(self, path: str) -> None:
        """使指定路径的缓存失效。"""
        self._cache.pop(path, None)

    def clear(self) -> None:
        """清空全部缓存。"""
        self._cache.clear()

    @property
    def size(self) -> int:
        """当前缓存条目数。"""
        return len(self._cache)
