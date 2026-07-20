from nli_detector.segmenter import claims, sentences


def test_sentences_split_on_period():
    text = "The claim is due tomorrow. Please confirm."
    assert sentences(text) == ["The claim is due tomorrow.", "Please confirm."]


def test_abbreviations_do_not_split():
    text = "Dr. Smith reviewed the claim. It looked fine."
    assert sentences(text) == ["Dr. Smith reviewed the claim.", "It looked fine."]


def test_coord_split_when_both_sides_propositional():
    text = "The premium is $500, and the deductible is $250."
    cs = claims(text)
    assert cs == ["The premium is $500", "the deductible is $250."]


def test_no_coord_split_when_rhs_is_a_noun_phrase():
    text = "We shipped payments in January, and February."
    cs = claims(text)
    # Only one claim — RHS lacks a verb.
    assert len(cs) == 1


def test_claims_filters_short_fragments():
    text = "Yes. The claim was approved."
    assert claims(text) == ["The claim was approved."]
