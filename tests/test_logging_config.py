import logging
import pytest
from src.logging_config import configure_logging, get_logger, log_tool

def test_configure_logging_allows_debug():
    configure_logging("DEBUG")
    log = get_logger("tools.test")
    assert log.isEnabledFor(logging.DEBUG)

def test_log_tool_decorator_wraps_and_logs(caplog):
    caplog.set_level(logging.DEBUG)

    @log_tool("demo")
    def add(a, b):
        return a + b

    with caplog.at_level(logging.DEBUG, logger="tools.demo"):
        out = add(2, 3)

    assert out == 5
    assert any("start args=" in rec.message for rec in caplog.records if rec.name == "tools.demo")
