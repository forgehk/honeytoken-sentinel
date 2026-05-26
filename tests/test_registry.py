import json
import pytest
from honeytoken import tokens
from honeytoken.registry import Registry


def test_add_and_get_token(tmp_path):
    r = Registry(tmp_path / "reg.json")
    t = tokens.mint_aws_key()
    r.add_token(t)
    assert r.get(t.token_id) is not None
    assert r.get("nope") is None


def test_persists_across_instances(tmp_path):
    p = tmp_path / "reg.json"
    r1 = Registry(p)
    t = tokens.mint_github_pat()
    r1.add_token(t)

    r2 = Registry(p)
    assert len(r2.tokens) == 1
    assert r2.tokens[0].token_id == t.token_id


def test_duplicate_token_id_rejected(tmp_path):
    r = Registry(tmp_path / "reg.json")
    t = tokens.mint_aws_key()
    r.add_token(t)
    with pytest.raises(ValueError):
        r.add_token(t)


def test_record_trigger_creates_event(tmp_path):
    r = Registry(tmp_path / "reg.json")
    t = tokens.mint_canary_url("https://x.example.com")
    r.add_token(t)
    evt = r.record_trigger(t.token_id, source_ip="10.0.0.5", user_agent="curl/7.88")
    assert evt.token_id == t.token_id
    assert evt.source_ip == "10.0.0.5"
    assert r.events_for(t.token_id) == [evt]


def test_record_trigger_unknown_raises(tmp_path):
    r = Registry(tmp_path / "reg.json")
    with pytest.raises(KeyError):
        r.record_trigger("nonsense")


def test_registry_file_is_valid_json(tmp_path):
    p = tmp_path / "reg.json"
    r = Registry(p)
    t = tokens.mint_stripe_key()
    r.add_token(t)
    r.record_trigger(t.token_id, source_ip="1.2.3.4")

    data = json.loads(p.read_text())
    assert "tokens" in data and "events" in data
    assert len(data["tokens"]) == 1
    assert len(data["events"]) == 1
