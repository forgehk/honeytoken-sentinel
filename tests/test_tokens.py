from honeytoken import tokens


def test_aws_key_shape():
    t = tokens.mint_aws_key()
    assert t.kind == "aws_key"
    assert "AKIA" in t.value
    assert "aws_access_key_id" in t.value
    assert "aws_secret_access_key" in t.value
    assert t.token_id.startswith("aws_")
    assert len(t.metadata["access_key"]) == 20   # AKIA + 16 chars


def test_github_pat_shape():
    t = tokens.mint_github_pat()
    assert t.value.startswith("github_pat_")
    assert len(t.value) > 80


def test_stripe_key_shape():
    t = tokens.mint_stripe_key()
    assert t.value.startswith("sk_live_")


def test_canary_url_embeds_token_id():
    t = tokens.mint_canary_url("https://canary.example.com/")
    assert t.value.startswith("https://canary.example.com/c/")
    # the token_id must be present in the URL so listener can extract it
    assert t.token_id in t.value


def test_decoy_doc_has_watermark():
    t = tokens.mint_decoy_doc("salaries.xlsx")
    assert t.value == "salaries.xlsx"
    assert t.metadata["watermark"] == t.token_id


def test_tokens_are_unique():
    a = tokens.mint_aws_key()
    b = tokens.mint_aws_key()
    assert a.token_id != b.token_id
    assert a.value != b.value


def test_detect_in_text_finds_aws_key():
    t = tokens.mint_aws_key()
    log = f"DEBUG configured with {t.metadata['access_key']} for region us-east-1"
    hits = tokens.detect_in_text(log, [t])
    assert len(hits) == 1
    assert hits[0].token_id == t.token_id


def test_detect_in_text_finds_url_by_token_id():
    t = tokens.mint_canary_url("https://canary.example.com")
    log = f"GET /c/{t.token_id} 200 from 10.0.0.5"
    hits = tokens.detect_in_text(log, [t])
    assert len(hits) == 1


def test_detect_in_text_misses_unrelated():
    t = tokens.mint_aws_key()
    other = tokens.mint_aws_key()
    log = f"key in use: {other.metadata['access_key']}"
    hits = tokens.detect_in_text(log, [t])
    assert hits == []
