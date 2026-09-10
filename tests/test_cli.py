from click.testing import CliRunner

from direct_transfer.__main__ import main


def test_help_and_version():
    runner = CliRunner()
    help_result = runner.invoke(main, ["--help"])
    assert help_result.exit_code == 0
    assert "--port" in help_result.output
    version_result = runner.invoke(main, ["--version"])
    assert version_result.exit_code == 0
    assert "0.1.0" in version_result.output


def test_invalid_port():
    result = CliRunner().invoke(main, ["--port", "70000"])
    assert result.exit_code == 2
    assert "between 1 and 65535" in result.output
