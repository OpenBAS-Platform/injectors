import json
from unittest import TestCase

from nuclei.helpers.nuclei_output_parser import NucleiOutputParser

parser = NucleiOutputParser()


class NucleiOutputParserTest(TestCase):

    def test_parse_single_cve_line(self):
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
        result = parser.parse(stdout, {})
        assert result["outputs"]["cve"] == [
            {
                "severity": "high",
                "host": ["https://example.com"],
                "id": "CVE-2021-1234",
                "asset_id": [""],
            }
        ]
        assert "1 CVE" in result["message"]

    def test_parse_multiple_lines_with_duplicates(self):
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
        result = parser.parse(stdout, {"host1": "asset1_id"})
        assert len(result["outputs"]["cve"]) == 1
        assert result["outputs"]["cve"][0]["asset_id"] == ["asset1_id"]

    def test_parse_multiple_lines_with_same_CVES(self):
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
                        "host": "host2",
                    }
                ),
            ]
        )
        result = parser.parse(stdout, {"host1": "asset1_id", "host2": "asset2_id"})
        assert len(result["outputs"]["cve"]) == 1
        assert result["outputs"]["cve"][0]["asset_id"] == ["asset1_id", "asset2_id"]

    def test_parse_with_text_output(self):
        stdout = "Some plain text vuln result\nAnother result line"
        result = parser.parse(stdout, {})
        assert result["outputs"]["cve"] == []
        assert result["outputs"]["others"] == [
            "Some plain text vuln result",
            "Another result line",
        ]
        assert "2 Vulnerabilities" in result["message"]
