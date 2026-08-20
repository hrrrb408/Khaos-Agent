"""Windows authority service lifecycle contract tests (M6.9 BATCH 8).

The Windows service binary only builds and runs on Windows; these tests
pin the source-level lifecycle contract that the Windows CI job executes
for real:

- SERVICE_CONTROL_STOP reports STOP_PENDING, sets a stop event, and the
  service loop observes it, cancels its pending accept, drains, and
  reports STOPPED (never a bare ``return 0`` from the handler);
- ConnectNamedPipe handles the legal ERROR_PIPE_CONNECTED race;
- client and backend pipe IO are overlapped with hard deadlines and
  CancelIoEx (no unbounded blocking on a wedged peer);
- responses and disconnects always reach a deterministic terminal state.
"""

from __future__ import annotations

from pathlib import Path

SOURCE = (
    Path(__file__).resolve().parents[3]
    / "rust"
    / "khaos-core"
    / "src"
    / "bin"
    / "khaos-authorityd-windows.rs"
)


def _source() -> str:
    return SOURCE.read_text(encoding="utf-8")


def test_stop_handler_reports_pending_and_signals_event() -> None:
    source = _source()
    assert "SERVICE_CONTROL_STOP" in source
    # The handler must not just return: it reports STOP_PENDING and sets
    # the stop event the loop waits on.
    assert "set_service_state(SERVICE_STOP_PENDING, 0, 10_000)" in source
    assert "SetEvent(event)" in source
    assert "CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())" in source


def test_stop_reports_stopped_after_drain() -> None:
    source = _source()
    assert "set_service_state(SERVICE_STOPPED, 0, 0)" in source
    # The stop path cancels the pending accept through one helper that
    # reaps the OVERLAPPED operation before disconnecting the pipe.
    assert "cancel_and_reap(" in source
    assert "GetOverlappedResult(handle, overlapped" in source
    assert "DisconnectNamedPipe(handle)" in source


def test_connect_race_is_handled() -> None:
    source = _source()
    assert "ERROR_PIPE_CONNECTED" in source
    # The race is treated as a successful connection, not an error.
    assert "the client already connected" in source


def test_pipe_io_is_overlapped_with_deadlines() -> None:
    source = _source()
    assert "FILE_FLAG_OVERLAPPED" in source
    assert "read_message_deadline" in source
    assert "write_message_deadline" in source
    assert "CLIENT_IO_TIMEOUT_MS" in source
    assert "BACKEND_IO_TIMEOUT_MS" in source
    # Deadlines actually cancel and reap the IO instead of waiting forever.
    assert source.count("cancel_and_reap(") >= 5
    assert "CancelIoEx(handle, overlapped)" in source
    assert "ERROR_OPERATION_ABORTED" in source


def test_backend_and_service_pipes_are_bounded() -> None:
    source = _source()
    assert "MAX_MESSAGE_BYTES" in source
    # The backend response is checked for bounds before parsing.
    assert "bytes.is_empty() && bytes.len() <= MAX_MESSAGE_BYTES" in source


def test_backend_startup_has_a_bounded_readiness_handshake() -> None:
    source = _source()
    # SCM can report the backend host as running before its Python child has
    # created the backend pipe.  The frontend must absorb that startup race
    # within a hard deadline instead of failing the first production probe.
    assert "WaitNamedPipeW" in source
    assert "open_backend_pipe" in source
    assert "BACKEND_CONNECT_TIMEOUT_MS" in source


def test_frontend_error_envelope_cannot_be_misreported_as_transport_proof() -> None:
    source = _source()
    assert "fn frontend_error" in source
    assert '"error_code"' in source
    # Backend data is untrusted with respect to the frontend transport
    # binding; it may not replace the native transport or proof digest.
    assert 'key != "native_transport" && key != "proof_digest"' in source
    assert '"native_peer_identity_mismatch"' in source


def test_service_accepts_stop_control() -> None:
    source = _source()
    assert "SERVICE_ACCEPT_STOP" in source
    assert "RegisterServiceCtrlHandlerExW" in source
    assert "StartServiceCtrlDispatcherW" in source
