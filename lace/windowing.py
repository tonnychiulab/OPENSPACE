from __future__ import annotations

from collections import deque
from datetime import timedelta

from lace.models import NormalizedEvent


class SlidingWindow:
    """Per-key deque window. Events stay sorted by timestamp; span ≤ window_seconds.

    Out-of-order timestamps are inserted by time, not arrival order. An event older
    than ``newest - window_seconds`` is dropped instead of stretching the window.
    """

    def __init__(self) -> None:
        self._events: deque[NormalizedEvent] = deque()

    def __iter__(self):
        return iter(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def as_list(self) -> list[NormalizedEvent]:
        return list(self._events)

    def add(self, event: NormalizedEvent, window_seconds: int) -> None:
        if self._events:
            newest = self._events[-1].timestamp
            if event.timestamp > newest:
                newest = event.timestamp
            cutoff = newest - timedelta(seconds=window_seconds)
            if event.timestamp < cutoff:
                return
        self._insert_sorted(event)
        self._evict(window_seconds)

    def _insert_sorted(self, event: NormalizedEvent) -> None:
        if not self._events or event.timestamp >= self._events[-1].timestamp:
            self._events.append(event)
            return
        tmp = list(self._events)
        lo, hi = 0, len(tmp)
        while lo < hi:
            mid = (lo + hi) // 2
            if tmp[mid].timestamp <= event.timestamp:
                lo = mid + 1
            else:
                hi = mid
        tmp.insert(lo, event)
        self._events = deque(tmp)

    def _evict(self, window_seconds: int) -> None:
        if not self._events:
            return
        cutoff = self._events[-1].timestamp - timedelta(seconds=window_seconds)
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()


class WindowManager:
    """Map of sliding windows keyed by src_ip or 'src_ip|dst_ip'."""

    def __init__(self) -> None:
        self._windows: dict[str, SlidingWindow] = {}

    def add(
        self, key: str, event: NormalizedEvent, window_seconds: int
    ) -> list[NormalizedEvent]:
        window = self._windows.setdefault(key, SlidingWindow())
        window.add(event, window_seconds)
        return window.as_list()
