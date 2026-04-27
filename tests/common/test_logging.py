"""Tests for library logging behaviour."""

import io


def test_import_authsome_produces_no_log_output():
    """Importing authsome must not emit any log output — library best practice."""
    from loguru import logger

    sink = io.StringIO()
    sink_id = logger.add(sink, level="DEBUG")
    try:
        import authsome  # noqa: F401

        output = sink.getvalue()
        assert output == "", f"Expected no log output on import, got: {output!r}"
    finally:
        logger.remove(sink_id)


def test_user_can_enable_authsome_logs():
    """Users should be able to opt-in and out of library logs without errors."""
    from loguru import logger

    logger.enable("authsome")
    logger.disable("authsome")  # restore default — must not raise


def test_cli_verbose_flag_does_not_crash(tmp_path):
    """--verbose flag must be accepted without error."""
    from unittest.mock import MagicMock, patch

    from click.testing import CliRunner

    from authsome.cli import cli

    runner = CliRunner()
    with patch("authsome.cli.AuthsomeContext") as mock_cls:
        ctx = MagicMock()
        ctx.vault._home = tmp_path
        mock_cls.create.return_value = ctx
        result = runner.invoke(cli, ["--verbose", "init"])
    assert result.exit_code == 0, result.output


def test_cli_log_file_creates_file(tmp_path):
    """--log-file PATH must create the log file after a command runs."""
    from unittest.mock import MagicMock, patch

    from click.testing import CliRunner

    from authsome.cli import cli

    log_path = tmp_path / "test.log"
    runner = CliRunner()
    with patch("authsome.cli.AuthsomeContext") as mock_cls:
        ctx = MagicMock()
        ctx.vault._home = tmp_path
        mock_cls.create.return_value = ctx
        result = runner.invoke(cli, ["--log-file", str(log_path), "init"])
    assert result.exit_code == 0, result.output
    assert log_path.exists(), "Log file should have been created"
