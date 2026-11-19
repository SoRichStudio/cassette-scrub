from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from cassette_scrub.parser import dump_cassette, is_vcr_cassette, load_cassette


class TestIsVcrCassette:
    """Tests for VCR.py cassette structure validation."""

    def test_valid_cassettes(
        self,
        sample_cassette_dict: dict[str, Any],
        clean_cassette_dict: dict[str, Any],
    ) -> None:
        assert is_vcr_cassette(sample_cassette_dict) is True
        assert is_vcr_cassette(clean_cassette_dict) is True

    def test_empty_interactions_list_is_valid(self) -> None:
        assert is_vcr_cassette({"version": 1, "interactions": []}) is True
        assert is_vcr_cassette({"interactions": []}) is True

    def test_multiple_valid_interactions(self) -> None:
        data = {
            "version": 1,
            "interactions": [
                {"request": {"method": "GET"}, "response": {"status": {"code": 200}}},
                {"request": {"method": "POST"}, "response": {"status": {"code": 201}}},
            ],
        }
        assert is_vcr_cassette(data) is True

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            [],
            "interactions",
            42,
            {},
            {"version": 1},
            {"interactions": None},
            {"interactions": {}},
            {"interactions": "not-a-list"},
            {"interactions": ["not-a-dict"]},
            {"interactions": [{"request": {}}]},
            {"interactions": [{"response": {}}]},
            {"interactions": [{"request": None, "response": {}}]},
            {"interactions": [{"request": {}, "response": "bad"}]},
            {
                "interactions": [
                    {"request": {}, "response": {}},
                    {"request": {}},
                ]
            },
        ],
    )
    def test_negative_cases(self, payload: Any) -> None:
        assert is_vcr_cassette(payload) is False


class TestLoadAndDumpCassette:
    """Tests for loading, skipping, and round-trip dumping of cassettes."""

    def test_round_trip_yaml(
        self,
        tmp_path: Path,
        yaml_cassette_path: Path,
        sample_cassette_dict: dict[str, Any],
    ) -> None:
        loaded, fmt = load_cassette(yaml_cassette_path)
        assert fmt == "yaml"
        assert loaded == sample_cassette_dict

        out_path = tmp_path / "round_trip.yaml"
        assert loaded is not None
        dump_cassette(out_path, loaded, fmt)

        reloaded, reloaded_fmt = load_cassette(out_path)
        assert reloaded_fmt == "yaml"
        assert reloaded == sample_cassette_dict

    def test_round_trip_yml(
        self,
        tmp_path: Path,
        sample_cassette_dict: dict[str, Any],
    ) -> None:
        yml_path = tmp_path / "cassette.yml"
        dump_cassette(yml_path, sample_cassette_dict, "yaml")

        loaded, fmt = load_cassette(yml_path)
        assert fmt == "yaml"
        assert loaded == sample_cassette_dict

    def test_round_trip_json(
        self,
        tmp_path: Path,
        json_cassette_path: Path,
        sample_cassette_dict: dict[str, Any],
    ) -> None:
        loaded, fmt = load_cassette(json_cassette_path)
        assert fmt == "json"
        assert loaded == sample_cassette_dict

        out_path = tmp_path / "round_trip.json"
        assert loaded is not None
        dump_cassette(out_path, loaded, fmt)

        raw_text = out_path.read_text(encoding="utf-8")
        assert raw_text.endswith("\n")
        assert json.loads(raw_text) == sample_cassette_dict

        reloaded, reloaded_fmt = load_cassette(out_path)
        assert reloaded_fmt == "json"
        assert reloaded == sample_cassette_dict

    def test_unicode_preserved_in_yaml_round_trip(self, tmp_path: Path) -> None:
        cassette = {
            "version": 1,
            "interactions": [
                {
                    "request": {
                        "method": "GET",
                        "uri": "https://api.example.com/v1/greet",
                        "body": None,
                        "headers": {},
                    },
                    "response": {
                        "status": {"code": 200, "message": "OK"},
                        "headers": {},
                        "body": {"string": "café — 日本語"},
                    },
                }
            ],
        }
        path = tmp_path / "unicode.yaml"
        dump_cassette(path, cassette, "yaml")
        assert "café — 日本語" in path.read_text(encoding="utf-8")

        loaded, fmt = load_cassette(path)
        assert fmt == "yaml"
        assert loaded == cassette

    def test_skips_non_cassette_yaml_and_json(
        self,
        tmp_path: Path,
        non_cassette_yaml_path: Path,
    ) -> None:
        assert load_cassette(non_cassette_yaml_path) == (None, "")

        non_cassette_json = tmp_path / "package.json"
        non_cassette_json.write_text(
            json.dumps({"name": "demo", "version": "1.0.0"}),
            encoding="utf-8",
        )
        assert load_cassette(non_cassette_json) == (None, "")

        list_yaml = tmp_path / "items.yml"
        list_yaml.write_text(yaml.safe_dump([1, 2, 3]), encoding="utf-8")
        assert load_cassette(list_yaml) == (None, "")

    def test_invalid_syntax_binary_junk_and_missing_files(
        self,
        tmp_path: Path,
        clean_cassette_dict: dict[str, Any],
    ) -> None:
        bad_yaml = tmp_path / "broken.yaml"
        bad_yaml.write_text("interactions:\n  - [unclosed", encoding="utf-8")
        assert load_cassette(bad_yaml) == (None, "")

        bad_json = tmp_path / "broken.json"
        bad_json.write_text("{not valid json", encoding="utf-8")
        assert load_cassette(bad_json) == (None, "")

        bad_utf8 = tmp_path / "bad_encoding.yaml"
        bad_utf8.write_bytes(b"\xff\xfe\x00\x80")
        assert load_cassette(bad_utf8) == (None, "")

        missing = tmp_path / "does_not_exist.yaml"
        assert load_cassette(missing) == (None, "")

        assert load_cassette(tmp_path) == (None, "")

        wrong_ext = tmp_path / "cassette.txt"
        wrong_ext.write_text(json.dumps(clean_cassette_dict), encoding="utf-8")
        assert load_cassette(wrong_ext) == (None, "")

    def test_yaml_binary_bytes_body_preservation(self, tmp_path: Path) -> None:
        binary_payload = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\xff\xfe\x80\x81"
        cassette: dict[str, Any] = {
            "version": 1,
            "interactions": [
                {
                    "request": {
                        "method": "GET",
                        "uri": "https://api.example.com/v1/blob",
                        "body": None,
                        "headers": {},
                    },
                    "response": {
                        "status": {"code": 200, "message": "OK"},
                        "headers": {"Content-Encoding": ["gzip"]},
                        "body": {"string": binary_payload},
                    },
                }
            ],
        }

        yaml_path = tmp_path / "binary_cassette.yaml"
        dump_cassette(yaml_path, cassette, "yaml")

        raw_yaml = yaml_path.read_text(encoding="utf-8")
        assert "!!binary" in raw_yaml

        loaded, fmt = load_cassette(yaml_path)
        assert fmt == "yaml"
        assert loaded is not None
        loaded_body = loaded["interactions"][0]["response"]["body"]["string"]
        assert isinstance(loaded_body, bytes)
        assert loaded_body == binary_payload

        redumped_path = tmp_path / "binary_cassette_copy.yaml"
        dump_cassette(redumped_path, loaded, "yaml")
        assert "!!binary" in redumped_path.read_text(encoding="utf-8")
        reloaded, reloaded_fmt = load_cassette(redumped_path)
        assert reloaded_fmt == "yaml"
        assert reloaded == cassette

    def test_dump_cassette_invalid_format_raises(
        self,
        tmp_path: Path,
        clean_cassette_dict: dict[str, Any],
    ) -> None:
        with pytest.raises(ValueError):
            dump_cassette(tmp_path / "out.toml", clean_cassette_dict, "toml")
