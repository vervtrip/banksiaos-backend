#!/usr/bin/env python3
"""
Banksia OS — Structured Logging Service
Rotating JSON log file + request tracking hooks for Flask.
"""
import json, logging, logging.handlers, os, uuid, time
from datetime import datetime, timezone

_LOG_DIR = "/var/log/banksia-os"
_LOG_FILE = os.path.join(_LOG_DIR, "app.json")
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT = 5

_logger = None


def _make_record(level, message, extra=None):
    """Build a structured log entry as a dict."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        "logger": "banksia_os",
    }
    if extra:
        # Pop known keys into top-level, rest stays under `extra`
        for k in ("module", "function", "line", "request_id", "user",
                  "duration_ms", "path", "method", "status_code"):
            if k in extra:
                record[k] = extra.pop(k)
        if extra:
            record["extra"] = extra
    return record


class JsonFormatter(logging.Formatter):
    """Custom formatter that outputs JSON lines."""
    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "user"):
            log_entry["user"] = record.user
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms
        if hasattr(record, "path"):
            log_entry["path"] = record.path
            log_entry["method"] = getattr(record, "method", "GET")
            log_entry["status_code"] = getattr(record, "status_code", 200)
        return json.dumps(log_entry, default=str)


def init_logging(app=None):
    """Initialise the structured logger. If app is given, also attaches Flask hooks."""
    global _logger

    os.makedirs(_LOG_DIR, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        _LOG_FILE, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT
    )
    handler.setFormatter(JsonFormatter())
    handler.setLevel(logging.DEBUG)

    _logger = logging.getLogger("banksia_os")
    _logger.setLevel(logging.DEBUG)
    # Clear existing handlers to avoid duplicates on re-init
    _logger.handlers.clear()
    _logger.addHandler(handler)
    _logger.propagate = False

    # Also log to stderr (captured by journald via gunicorn)
    console = logging.StreamHandler()
    console.setFormatter(JsonFormatter())
    console.setLevel(logging.INFO)
    _logger.addHandler(console)

    if app is not None:
        _attach_flask_hooks(app)

    return _logger


def _attach_flask_hooks(app):
    """Attach before/after request hooks for automatic request logging."""
    import flask

    @app.before_request
    def _set_request_id():
        flask.g.request_id = uuid.uuid4().hex[:12]
        flask.g.start_time = time.time()

    @app.after_request
    def _log_request(response):
        if not hasattr(flask.g, "request_id"):
            return response
        duration = int((time.time() - flask.g.start_time) * 1000)
        user = flask.session.get("username", "anonymous") if hasattr(flask.g, "session") else "anonymous"
        try:
            user = flask.session.get("username", "anonymous")
        except Exception:
            user = "anonymous"

        _logger.info(
            f"{flask.request.method} {flask.request.path} -> {response.status_code}",
            extra={
                "request_id": flask.g.request_id,
                "user": user,
                "duration_ms": duration,
                "path": flask.request.path,
                "method": flask.request.method,
                "status_code": response.status_code,
            }
        )
        return response

    @app.teardown_request
    def _cleanup_request(exc=None):
        if hasattr(flask.g, "request_id"):
            flask.g.request_id = None


# Convenience wrappers
def log_info(msg, **extra):
    if _logger:
        _logger.info(msg, extra=extra)


def log_error(msg, **extra):
    if _logger:
        _logger.error(msg, extra=extra)


def log_warning(msg, **extra):
    if _logger:
        _logger.warning(msg, extra=extra)


def log_debug(msg, **extra):
    if _logger:
        _logger.debug(msg, extra=extra)


def get_logger():
    return _logger
