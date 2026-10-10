import contextlib
import io
import socket
import threading
import time
import unittest
from unittest.mock import patch

import smuggler


class SendRawTests(unittest.TestCase):
    def start_fixture(self, payload, linger=0):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.recv(16384)
                    connection.sendall(payload)
                    if linger:
                        time.sleep(linger)
            finally:
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        return port, worker

    def test_response_is_capped(self):
        port, worker = self.start_fixture(b"x" * (smuggler.MAX_RESPONSE_BYTES + 1))

        response, error = smuggler.send_raw(
            "127.0.0.1", port, b"local test", timeout=1
        )

        self.assertEqual(len(response), smuggler.MAX_RESPONSE_BYTES)
        self.assertEqual(error, "response exceeded 8192-byte limit")
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_timeout_returns_partial_response_and_error(self):
        port, worker = self.start_fixture(b"partial", linger=0.3)
        started = time.monotonic()

        response, error = smuggler.send_raw(
            "127.0.0.1", port, b"local test", timeout=0.1
        )

        self.assertEqual(response, b"partial")
        self.assertTrue(error.startswith("TimeoutError:"), error)
        self.assertLess(time.monotonic() - started, 0.25)
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_both_probes_remain_inconclusive_against_local_http_fixture(self):
        response = (
            b"HTTP/1.1 405 Method Not Allowed\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        for probe in (smuggler.cl_te_probe, smuggler.te_cl_probe):
            with self.subTest(technique=probe.__name__):
                port, worker = self.start_fixture(response)

                result = probe("127.0.0.1", port, "/", False, timeout=1)

                self.assertEqual(result["finding"], "inconclusive")
                self.assertFalse(result["confirmed_vulnerability"])
                self.assertEqual(result["parser_observation"], "http_error_status")
                self.assertIsNone(result["error"])
                worker.join(timeout=1)
                self.assertFalse(worker.is_alive())


class ResultTests(unittest.TestCase):
    def test_error_status_is_not_reported_as_confirmed_vulnerability(self):
        result = smuggler.probe_result(
            "CL.TE", b"HTTP/1.1 405 Method Not Allowed\r\n\r\n", None, 0.01
        )

        self.assertEqual(result["finding"], "inconclusive")
        self.assertFalse(result["confirmed_vulnerability"])
        self.assertEqual(result["parser_observation"], "http_error_status")

    def test_scope_mismatch_stops_before_any_connection(self):
        argv = [
            "smuggler.py", "127.0.0.1", "--port", "8080", "--no-ssl",
            "--scope", "127.0.0.1:8081",
        ]
        with patch("sys.argv", argv), patch.object(smuggler, "cl_te_probe") as probe:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_info:
                    smuggler.main()

        self.assertEqual(exit_info.exception.code, 2)
        probe.assert_not_called()

    def test_timeout_above_cap_stops_before_any_connection(self):
        argv = [
            "smuggler.py", "127.0.0.1", "--timeout", "5.1",
            "--scope", "127.0.0.1:443",
        ]
        with patch("sys.argv", argv), patch.object(smuggler, "cl_te_probe") as probe:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_info:
                    smuggler.main()

        self.assertEqual(exit_info.exception.code, 2)
        probe.assert_not_called()

    def test_ssl_context_verifies_certificates(self):
        context = smuggler.make_ssl_context(use_ssl=True)

        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, smuggler.ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
