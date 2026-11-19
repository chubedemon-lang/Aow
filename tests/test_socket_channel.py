"""Socket-channel integration tests using local socket pairs only."""

import socket
import threading
import unittest
from unittest.mock import patch

from server.frame_reader import CallbackFrameReader, TruncatedFrame
from server.stream_reader import read_next_frame
from server.socket_channel import (
    SocketChannelClosed,
    SocketChannelWriteClosed,
    SocketFrameChannel,
)
from server.stream_writer import WritePayloadTooLarge


def synthetic_probe(prefix):
    """Test-only frame format: first byte is the remaining body length."""
    if not prefix:
        return None
    return prefix[0] + 1


class HostileSocket(socket.socket):
    """A socket subclass whose overridable methods must not be invoked."""

    def getsockopt(self, *args):
        raise AssertionError("custom socket getsockopt hook executed")


class DerivedFrameReader(CallbackFrameReader):
    """A reader subclass used to test the channel's exact-type boundary."""

    @property
    def closed(self):
        raise AssertionError("custom frame-reader property executed")


def make_channel(
    *,
    timeout=0.2,
    max_buffer_bytes=64,
    max_read_chunk_bytes=16,
    max_write_bytes=32,
    frame_timeout=None,
):
    local, peer = socket.socketpair()
    reader = CallbackFrameReader(
        synthetic_probe,
        max_frame_bytes=max_buffer_bytes,
        max_buffer_bytes=max_buffer_bytes,
        max_probe_bytes=1,
    )
    channel = SocketFrameChannel(
        local,
        reader,
        io_timeout_seconds=timeout,
        max_read_chunk_bytes=max_read_chunk_bytes,
        max_write_bytes=max_write_bytes,
        frame_timeout_seconds=frame_timeout,
    )
    return channel, peer, reader


def recv_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise AssertionError("peer closed before expected bytes arrived")
        result.extend(chunk)
    return bytes(result)


class SocketFrameChannelTests(unittest.TestCase):
    def test_receives_fragmented_frame_from_connected_socket(self):
        channel, peer, _reader = make_channel()
        try:
            peer.sendall(b"\x03a")
            peer.sendall(b"bc")
            self.assertEqual(channel.receive_frame(), b"\x03abc")
            self.assertFalse(channel.read_eof)
        finally:
            channel.close()
            peer.close()

    def test_drains_coalesced_frames_in_order(self):
        channel, peer, _reader = make_channel()
        try:
            peer.sendall(b"\x01A\x02BC")
            self.assertEqual(channel.receive_frame(), b"\x01A")
            self.assertEqual(channel.receive_frame(), b"\x02BC")
        finally:
            channel.close()
            peer.close()

    def test_socket_timeout_does_not_close_reader_or_discard_input(self):
        channel, peer, reader = make_channel(timeout=0.02)
        try:
            with self.assertRaises(socket.timeout):
                channel.receive_frame()
            self.assertFalse(reader.closed)
            self.assertEqual(reader.available, 0)
            self.assertFalse(channel.read_eof)

            peer.sendall(b"\x01A")
            self.assertEqual(channel.receive_frame(), b"\x01A")
        finally:
            channel.close()
            peer.close()

    def test_frame_deadline_persists_across_partial_reads_and_retries(self):
        channel, peer, reader = make_channel(timeout=1.0, frame_timeout=0.1)
        try:
            # The synthetic probe expects four total bytes. Two are already
            # buffered; one arrives before the total deadline, one remains late.
            reader.feed(b"\x03a")
            peer.sendall(b"b")
            with patch(
                "server.socket_channel.time.monotonic",
                side_effect=[10.0, 10.02, 10.11],
            ), patch(
                "server.socket_channel.select.select",
                return_value=([channel._socket], [], []),
            ):
                with self.assertRaises(socket.timeout):
                    channel.receive_frame()

            self.assertEqual(reader.peek(3), b"\x03ab")
            self.assertEqual(channel._pending_frame_deadline, 10.1)

            # A later receive call must not restart the deadline for the same
            # incomplete frame; the retained suffix remains inspectable.
            with patch("server.socket_channel.time.monotonic", return_value=10.12):
                with self.assertRaises(socket.timeout):
                    channel.receive_frame()
            self.assertEqual(reader.peek(3), b"\x03ab")
        finally:
            channel.close()
            peer.close()

    def test_frame_deadline_before_any_bytes_does_not_pin_a_frame(self):
        channel, peer, _reader = make_channel(timeout=1.0, frame_timeout=0.1)
        try:
            with patch(
                "server.socket_channel.time.monotonic",
                side_effect=[20.0, 20.11],
            ):
                with self.assertRaises(socket.timeout):
                    channel.receive_frame()
            self.assertIsNone(channel._pending_frame_deadline)
        finally:
            channel.close()
            peer.close()

    def test_clean_peer_half_close_keeps_local_write_direction_open(self):
        channel, peer, _reader = make_channel()
        try:
            peer.shutdown(socket.SHUT_WR)
            self.assertIsNone(channel.receive_frame())
            self.assertTrue(channel.read_eof)
            self.assertEqual(channel.send_bytes(b"ok"), 2)
            self.assertEqual(recv_exact(peer, 2), b"ok")
        finally:
            channel.close()
            peer.close()

    def test_local_write_half_close_is_idempotent_and_keeps_receives_open(self):
        channel, peer, _reader = make_channel()
        try:
            self.assertTrue(channel.shutdown_write())
            self.assertFalse(channel.shutdown_write())
            self.assertTrue(channel.write_eof)
            self.assertEqual(peer.recv(1), b"")

            with self.assertRaises(SocketChannelWriteClosed):
                channel.send_bytes(b"after-eof")

            peer.sendall(b"\x01A")
            self.assertEqual(channel.receive_frame(), b"\x01A")
            self.assertFalse(channel.read_eof)
        finally:
            channel.close()
            peer.close()

    def test_concurrent_writes_are_not_interleaved(self):
        payload_a = b"A" * 32768
        payload_b = b"B" * 32768
        channel, peer, _reader = make_channel(max_write_bytes=len(payload_a))
        peer.settimeout(3.0)
        channel._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        start = threading.Barrier(3)
        errors = []

        def send(payload):
            try:
                start.wait(timeout=2.0)
                channel.send_bytes(payload)
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=send, args=(payload_a,)),
            threading.Thread(target=send, args=(payload_b,)),
        ]
        try:
            for thread in threads:
                thread.start()
            start.wait(timeout=2.0)
            wire = recv_exact(peer, len(payload_a) + len(payload_b))
            for thread in threads:
                thread.join(timeout=3.0)

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertIn(wire, (payload_a + payload_b, payload_b + payload_a))
        finally:
            channel.close()
            peer.close()
            for thread in threads:
                if thread.is_alive():
                    thread.join(timeout=1.0)

    def test_truncated_peer_eof_preserves_buffered_suffix_and_marks_eof(self):
        channel, peer, reader = make_channel()
        try:
            peer.sendall(b"\x03a")
            peer.shutdown(socket.SHUT_WR)
            with self.assertRaises(TruncatedFrame) as caught:
                channel.receive_frame()
            self.assertEqual((caught.exception.expected, caught.exception.available), (4, 2))
            self.assertEqual(reader.available, 2)
            self.assertTrue(reader.closed)
            self.assertTrue(channel.read_eof)
            self.assertIsNone(channel.receive_frame())
        finally:
            channel.close()
            peer.close()

    def test_send_bytes_uses_bounded_partial_write_helper(self):
        channel, peer, _reader = make_channel()
        try:
            self.assertEqual(channel.send_bytes(b"server-bytes"), 12)
            self.assertEqual(recv_exact(peer, 12), b"server-bytes")
        finally:
            channel.close()
            peer.close()

    def test_write_limit_rejects_before_any_socket_bytes_are_sent(self):
        channel, peer, _reader = make_channel(max_write_bytes=3)
        try:
            peer.settimeout(0.02)
            with self.assertRaises(WritePayloadTooLarge):
                channel.send_bytes(b"four")
            with self.assertRaises(socket.timeout):
                peer.recv(1)
        finally:
            channel.close()
            peer.close()

    def test_close_is_idempotent_and_rejects_future_operations(self):
        channel, peer, _reader = make_channel()
        self.assertTrue(channel.close())
        self.assertFalse(channel.close())
        self.assertTrue(channel.closed)
        self.assertTrue(channel.write_eof)
        self.assertEqual(peer.recv(1), b"")
        with self.assertRaises(SocketChannelClosed):
            channel.receive_frame()
        with self.assertRaises(SocketChannelClosed):
            channel.send_bytes(b"x")
        peer.close()

    def test_close_interrupts_blocked_receive(self):
        channel, peer, _reader = make_channel(timeout=2.0)
        read_started = threading.Event()
        outcomes = []
        original_read_next_frame = read_next_frame

        def observe_read(reader, recv, *, max_chunk_bytes):
            def observed_recv(size):
                read_started.set()
                return recv(size)

            return original_read_next_frame(
                reader, observed_recv, max_chunk_bytes=max_chunk_bytes
            )

        def receive():
            try:
                outcomes.append(channel.receive_frame())
            except BaseException as exc:
                outcomes.append(exc)

        thread = threading.Thread(target=receive)
        try:
            with patch(
                "server.socket_channel.read_next_frame",
                side_effect=observe_read,
            ):
                thread.start()
                self.assertTrue(read_started.wait(timeout=1.0))
                self.assertTrue(channel.close())
                thread.join(timeout=1.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(len(outcomes), 1)
            # Depending on whether shutdown or close wins the recv race, the
            # blocked call observes clean EOF or the socket's close error.
            self.assertTrue(outcomes[0] is None or isinstance(outcomes[0], OSError))
            self.assertTrue(channel.closed)
        finally:
            channel.close()
            peer.close()
            if thread.is_alive():
                thread.join(timeout=1.0)

    def test_context_manager_closes_owned_socket(self):
        channel, peer, _reader = make_channel()
        with channel as active:
            self.assertIs(active, channel)
            self.assertFalse(channel.closed)
        self.assertTrue(channel.closed)
        self.assertEqual(peer.recv(1), b"")
        peer.close()

    def test_constructor_rejects_invalid_timeout_and_limits(self):
        local, peer = socket.socketpair()
        reader = CallbackFrameReader(
            synthetic_probe,
            max_frame_bytes=8,
            max_buffer_bytes=8,
            max_probe_bytes=1,
        )
        try:
            for timeout in (0.0, -1.0, float("inf"), float("nan"), 1, True):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    SocketFrameChannel(local, reader, io_timeout_seconds=timeout)

            for frame_timeout in (
                0.0, -1.0, float("inf"), float("nan"), 1, True, "1",
            ):
                with self.subTest(frame_timeout=frame_timeout), self.assertRaises(ValueError):
                    SocketFrameChannel(
                        local, reader, frame_timeout_seconds=frame_timeout
                    )

            for kwargs in (
                {"max_read_chunk_bytes": 0},
                {"max_read_chunk_bytes": True},
                {"max_write_bytes": 0},
                {"max_write_bytes": True},
            ):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    SocketFrameChannel(local, reader, **kwargs)

            with self.assertRaises(TypeError):
                SocketFrameChannel(local, object())
        finally:
            local.close()
            peer.close()

    def test_constructor_rejects_socket_subclasses_before_custom_methods(self):
        reader = CallbackFrameReader(
            synthetic_probe,
            max_frame_bytes=8,
            max_buffer_bytes=8,
            max_probe_bytes=1,
        )
        hostile = HostileSocket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaisesRegex(TypeError, "exact socket.socket"):
                SocketFrameChannel(hostile, reader)
        finally:
            hostile.close()

    def test_constructor_rejects_frame_reader_subclasses(self):
        local, peer = socket.socketpair()
        reader = DerivedFrameReader(
            synthetic_probe,
            max_frame_bytes=8,
            max_buffer_bytes=8,
            max_probe_bytes=1,
        )
        try:
            with self.assertRaisesRegex(TypeError, "exact CallbackFrameReader"):
                SocketFrameChannel(local, reader)
        finally:
            local.close()
            peer.close()

    def test_constructor_rejects_datagram_and_unconnected_sockets(self):
        reader = CallbackFrameReader(
            synthetic_probe,
            max_frame_bytes=8,
            max_buffer_bytes=8,
            max_probe_bytes=1,
        )
        datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with self.assertRaises(ValueError):
                SocketFrameChannel(datagram, reader)
        finally:
            datagram.close()

        unconnected = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(ValueError):
                SocketFrameChannel(unconnected, reader)
        finally:
            unconnected.close()


if __name__ == "__main__":
    unittest.main()
