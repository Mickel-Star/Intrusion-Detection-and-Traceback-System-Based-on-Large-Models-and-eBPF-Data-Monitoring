import unittest

from src.process.streaming_reduction import (
    SlidingWindowConfig,
    SlidingWindowReducer,
    StreamingReducer,
    StreamingReductionConfig,
)


def synthetic_event(minute: int) -> dict:
    return {
        "timestamp": float(minute * 60),
        "uid": 0,
        "comm": f"proc_{minute}",
        "pid": 1000 + int(minute),
        "tid": 1000 + int(minute),
        "ret": 3,
        "event": "openat",
        "args": {
            "pathname": f"/tmp/sliding_window_file_{minute}",
            "inode": str(10_000 + int(minute)),
        },
        "container_id": "abcdef1234567890",
        "container_image": "synthetic:latest",
    }


def synthetic_events(minutes: int):
    return [synthetic_event(minute) for minute in range(minutes)]


class SlidingWindowReducerTest(unittest.TestCase):
    def test_sliding_windows_emit_expected_boundaries(self):
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
            )
        )

        windows = []
        for event in synthetic_events(51):
            windows.extend(reducer.add_event(event))

        self.assertEqual(3, len(windows))
        self.assertEqual(
            [(0.0, 1800.0), (600.0, 2400.0), (1200.0, 3000.0)],
            [(window.window_start, window.window_end) for window in windows],
        )
        self.assertTrue(all(window.complete for window in windows))
        self.assertEqual([30, 30, 30], [window.event_count for window in windows])
        self.assertTrue(all(window.graph.number_of_nodes() > 0 for window in windows))
        self.assertTrue(all(window.graph.number_of_edges() > 0 for window in windows))

        overlaps = [
            min(left.window_end, right.window_end) - max(left.window_start, right.window_start)
            for left, right in zip(windows, windows[1:])
        ]
        self.assertEqual([1200.0, 1200.0], overlaps)

    def test_finalize_can_emit_remaining_available_window(self):
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=1800,
                stride_seconds=600,
                time_bin_seconds=30,
            )
        )

        windows = []
        for event in synthetic_events(50):
            windows.extend(reducer.add_event(event))
        windows.extend(reducer.finalize(emit_partial=True))

        self.assertEqual(3, len(windows))
        self.assertEqual((1200.0, 3000.0), (windows[-1].window_start, windows[-1].window_end))
        self.assertFalse(windows[-1].complete)
        self.assertEqual(30, windows[-1].event_count)
        self.assertEqual([], reducer.finalize(emit_partial=True))

    def test_streaming_reducer_still_uses_tumbling_windows(self):
        reducer = StreamingReducer(
            config=StreamingReductionConfig(
                window_seconds=1800,
                time_bin_seconds=30,
            )
        )

        windows = list(reducer.ingest_logs(synthetic_events(51)))

        self.assertEqual(2, len(windows))
        first_graph, _first_metas = windows[0]
        second_graph, _second_metas = windows[1]
        self.assertGreater(first_graph.number_of_edges(), 0)
        self.assertGreater(second_graph.number_of_edges(), 0)
        self.assertNotIn("sliding_window_config", first_graph.graph)


if __name__ == "__main__":
    unittest.main()
