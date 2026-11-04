from scripts.evaluate_detection import evaluate_detection


def test_labeled_detection_dataset_has_perfect_recall():
    result = evaluate_detection()

    assert result["recall"] == 1.0
    assert result["precision"] >= 0.95
