from __future__ import annotations

from khaos.cli.main import build_command_parser


def test_coding_eval_cli_exposes_list_run_report_and_compare() -> None:
    parser = build_command_parser()

    listed = parser.parse_args(["eval", "coding", "list", "--json"])
    run = parser.parse_args(["eval", "coding", "run", "bugfix-python-cache"])
    tagged = parser.parse_args(["eval", "coding", "run", "--tag", "smoke"])
    report = parser.parse_args(["eval", "coding", "report", "m8-run", "--format", "json"])
    compared = parser.parse_args(["eval", "coding", "compare", "m8-a", "m8-b"])

    assert (listed.eval_command, listed.coding_command, listed.as_json) == (
        "coding",
        "list",
        True,
    )
    assert run.scenario_id == "bugfix-python-cache"
    assert tagged.tag == "smoke"
    assert report.format == "json"
    assert report.run_id_positional == "m8-run"
    assert (compared.baseline_run_id, compared.candidate_run_id) == ("m8-a", "m8-b")
