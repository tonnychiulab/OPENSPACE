from datetime import timedelta

from lace.windowing import SlidingWindow, WindowManager
from tests.conftest import BASE, event


def test_evicts_events_older_than_window():
    window = SlidingWindow()
    src, dst = "192.0.2.1", "198.51.100.1"
    for second in (0, 10, 20, 70):
        window.add(event(second, src, dst, dst_port=second + 1), window_seconds=60)
    times = [e.timestamp for e in window]
    assert times[0] == BASE + timedelta(seconds=10)
    assert times[-1] == BASE + timedelta(seconds=70)
    assert len(window) == 3


def test_out_of_order_timestamp_inserts_by_time_not_arrival():
    window = SlidingWindow()
    src, dst = "192.0.2.1", "198.51.100.1"
    window.add(event(0, src, dst, dst_port=1), window_seconds=30)
    window.add(event(20, src, dst, dst_port=2), window_seconds=30)
    window.add(event(10, src, dst, dst_port=3), window_seconds=30)
    ports = [e.dst_port for e in window]
    assert ports == [1, 3, 2]


def test_out_of_order_event_older_than_window_is_dropped():
    window = SlidingWindow()
    src, dst = "192.0.2.1", "198.51.100.1"
    window.add(event(100, src, dst, dst_port=1), window_seconds=30)
    window.add(event(0, src, dst, dst_port=99), window_seconds=30)
    assert [e.dst_port for e in window] == [1]


def test_window_manager_isolates_keys():
    mgr = WindowManager()
    a = event(0, "192.0.2.1", "198.51.100.1", dst_port=1)
    b = event(0, "192.0.2.2", "198.51.100.1", dst_port=2)
    mgr.add("192.0.2.1", a, 60)
    view = mgr.add("192.0.2.2", b, 60)
    assert len(view) == 1
    assert view[0].src_ip == "192.0.2.2"
