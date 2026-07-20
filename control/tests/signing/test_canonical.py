from guardx_control.signing.canonical import canonical_json, sha256_hex


def test_canonical_sorts_keys_deeply():
    doc = {"b": 1, "a": {"z": 2, "y": [3, {"n": 4, "m": 5}]}}
    out = canonical_json(doc)
    assert out == b'{"a":{"y":[3,{"m":5,"n":4}],"z":2},"b":1}'


def test_canonical_is_stable_across_input_ordering():
    d1 = {"a": 1, "b": 2}
    d2 = {"b": 2, "a": 1}
    assert canonical_json(d1) == canonical_json(d2)
    assert sha256_hex(canonical_json(d1)) == sha256_hex(canonical_json(d2))


def test_canonical_no_whitespace_no_extras():
    out = canonical_json({"a": [1, 2, 3]})
    assert out == b'{"a":[1,2,3]}'


def test_canonical_unicode_preserved():
    out = canonical_json({"name": "Zoë"})
    assert out == '{"name":"Zoë"}'.encode("utf-8")
