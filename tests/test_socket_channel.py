"""Socket-channel integration tests using local socket pairs only."""

import socket
import unittest

from server.frame_reader import CallbackFrameReader, TruncatedFrame
from server.socket_channel import SocketChannelClosed, SocketFrameChannel
from server.stream_writer import WritePayloadTooLarge


def synthetic_probe(prefix):
    """Test-only frame format: first byte is the remaining body length."""
    if not prefix:
        return None
    return prefix[0] + 1


def make_channel(
    *,
    timeout=0.2,
    max_buffer_bytes=64,
    max_read_chunk_bytes=16,
    max_write_bytes=32,
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
        self.assertEqual(peer.recv(1), b"")
        with self.assertRaises(SocketChannelClosed):
            channel.receive_frame()
        with self.assertRaises(SocketChannelClosed):
            channel.send_bytes(b"x")
        peer.close()

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
