from malpdf.cli import main


def test_cli_reports_selected_seed(capsys):
    assert main(["--seed", "7"]) == 0
    assert capsys.readouterr().out == "malpdf ready (seed=7)\n"
