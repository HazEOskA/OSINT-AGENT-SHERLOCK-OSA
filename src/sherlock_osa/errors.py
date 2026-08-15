from __future__ import annotations


class SherlockError(Exception):
    """Typed user-facing error with a stable code."""

    def __init__(self, code: str, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_dict(self) -> dict[str, object]:
        return {"error": {"code": self.code, "message": self.message}}


class ConfigurationError(SherlockError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status=500)


class EngineError(SherlockError):
    def __init__(self, code: str, message: str, *, status: int = 502) -> None:
        super().__init__(code, message, status=status)
