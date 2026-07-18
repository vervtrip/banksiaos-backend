"""
Banksia OS — Error handling service layer.
Safe wrappers, logging decorators, and exception utilities.
"""
import logging, traceback
from functools import wraps
from flask import current_app

logger = logging.getLogger(__name__)


def safe_call(fn, *args, default=None, log_msg=None, **kwargs):
    """
    Call a function and return its result, or `default` on exception.
    Logs the error with traceback if an app context is available.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        if log_msg:
            try:
                current_app.logger.error(f"{log_msg}: {e}\n{traceback.format_exc()}")
            except RuntimeError:
                logger.error(f"{log_msg}: {e}\n{traceback.format_exc()}")
        return default


def safe_decorator(log_msg=None, default=None):
    """
    Decorator that wraps a function in try/except with logging.
    Usage: @safe_decorator(log_msg="Dashboard load failed")
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                msg = log_msg or f"Error in {fn.__name__}"
                try:
                    current_app.logger.error(f"{msg}: {e}\n{traceback.format_exc()}")
                except RuntimeError:
                    logger.error(f"{msg}: {e}\n{traceback.format_exc()}")
                return default
        return wrapper
    return decorator


def api_error_handler(fn):
    """
    Decorator for Flask route handlers.
    Catches exceptions and returns a JSON error response.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            try:
                current_app.logger.error(f"API error in {fn.__name__}: {e}\n{traceback.format_exc()}")
            except RuntimeError:
                logger.error(f"API error in {fn.__name__}: {e}\n{traceback.format_exc()}")
            from services.db_service import json_error
            return json_error(str(e), 500)
    return wrapper


def log_error(msg, exc_info=True):
    """Log an error to the current app's logger."""
    try:
        current_app.logger.error(msg, exc_info=exc_info)
    except RuntimeError:
        logger.error(msg, exc_info=exc_info)
