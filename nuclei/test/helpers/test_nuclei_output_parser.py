import json

from nuclei.src.helpers.nuclei_output_parser import NucleiOutputParser

parser = NucleiOutputParser()


def test_parse_single_cve_line():
    stdout = json.dumps(
        {
            "matcher-status": True,
            "info": {
                "classification": {"cve-id": ["CVE-2021-1234"]},
                "severity": "high",
            },
            "host": "https://example.com",
        }
    )
    result = parser.parse(stdout)
    assert result["outputs"]["cve"] == [
        {"severity": "high", "host": "https://example.com", "id": "CVE-2021-1234"}
    ]
    assert "1 CVE" in result["message"]


def test_parse_multiple_lines_with_duplicates():
    stdout = "\n".join(
        [
            json.dumps(
                {
                    "matcher-status": True,
                    "info": {
                        "classification": {"cve-id": ["CVE-2022-0001"]},
                        "severity": "medium",
                    },
                    "host": "host1",
                }
            ),
            json.dumps(
                {
                    "matcher-status": True,
                    "info": {
                        "classification": {"cve-id": ["CVE-2022-0001"]},
                        "severity": "medium",
                    },
                    "host": "host1",
                }
            ),
        ]
    )
    result = parser.parse(stdout)
    assert len(result["outputs"]["cve"]) == 1


def test_parse_with_text_output():
    stdout = "Some plain text vuln result\nAnother result line"
    result = parser.parse(stdout)
    assert result["outputs"]["cve"] == []
    assert result["outputs"]["others"] == [
        "Some plain text vuln result",
        "Another result line",
    ]
    assert "2 Vulnerabilities" in result["message"]
