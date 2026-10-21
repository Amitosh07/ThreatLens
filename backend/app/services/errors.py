"""Exceptions that are safe to show to a local user."""


class ThreatLensError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class TsharkNotFoundError(ThreatLensError):
    pass


class CaptureParseError(ThreatLensError):
    pass


class AnalysisTimeoutError(ThreatLensError):
    pass


class UnsafePathError(ThreatLensError):
    pass
