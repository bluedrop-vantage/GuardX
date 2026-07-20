from pii_detector.detector import scan, score
from pii_detector.entity_pack import load_pack


PACK = load_pack("financial-us@2.1")


def label_set(spans):
    return {s.label for s in spans}


def test_ssn_with_context_is_high_confidence():
    text = "Please confirm SSN 123-45-6789 on file."
    spans = scan(text, PACK)
    assert "SSN" in label_set(spans)
    ssn = next(s for s in spans if s.label == "SSN")
    assert ssn.confidence >= 0.90  # context boost applied


def test_credit_card_requires_luhn():
    good = "Card 4242 4242 4242 4242 charged $50."
    bad = "Random 1234 5678 9012 3456 not a card."
    good_spans = scan(good, PACK)
    bad_spans = scan(bad, PACK)
    assert "CREDIT_CARD" in label_set(good_spans)
    assert "CREDIT_CARD" not in label_set(bad_spans)


def test_email_is_detected():
    text = "Reach out at first.last@example.co.uk any time."
    assert "EMAIL" in label_set(scan(text, PACK))


def test_bank_account_requires_context():
    with_ctx = "Deposit into account 123456789012."
    without_ctx = "Reference 123456789012 anywhere."
    assert "US_BANK_ACCOUNT" in label_set(scan(with_ctx, PACK))
    assert "US_BANK_ACCOUNT" not in label_set(scan(without_ctx, PACK))


def test_clean_text_produces_no_spans():
    text = "How can I reset my dashboard preferences to the default view?"
    spans = scan(text, PACK)
    # Allow zero false positives on innocuous prose.
    assert spans == []


def test_routing_number_checksum():
    # Real ABA — 021000021 (Chase NY).
    text = "Routing number 021000021 goes to the wire."
    assert "US_ROUTING" in label_set(scan(text, PACK))


def test_score_is_max_confidence():
    text = "SSN 123-45-6789 and email a@b.co"
    spans = scan(text, PACK)
    assert 0 < score(spans) <= 1.0
