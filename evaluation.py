
# ===== CELL 7: Evaluation (paste evaluation.py code) =====
"""
Evaluation metrics
"""
import jsonlines
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

import jsonlines


from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

import jsonlines


from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import os
import json
import jsonlines
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

import os
import json
import jsonlines
from collections import Counter
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

def evaluate_results(results_path, model_name, save_dir="evaluation_results"):
    """Evaluate prediction results and save metrics"""

    results = []

    with jsonlines.open(results_path) as reader:
        for obj in reader:
            results.append(obj)

    label_map = {
        'safe': 0,
        'suspicious': 1
    }

    reverse_label_map = {
        0: 'safe',
        1: 'suspicious'
    }

    y_true = []
    y_pred = []

    for r in results:

        gt = r.get('ground_truth')
        pred = r.get('predicted_label')

        if gt is None or pred is None:
            continue

        if isinstance(gt, str):
            gt = label_map.get(gt.strip().lower())

        if gt is None:
            continue

        y_true.append(int(gt))
        y_pred.append(int(pred))

    if len(y_true) == 0:
        print("No valid labeled samples found.")
        return None

    # -----------------------------
    # Print class distributions
    # -----------------------------
    true_counts = Counter(y_true)
    pred_counts = Counter(y_pred)

    print("\n========== Label Distribution ==========")
    print(f"Total valid samples: {len(y_true)}\n")

    print("Ground Truth:")
    for label in sorted(reverse_label_map):
        print(f"  Class {label} ({reverse_label_map[label]}): {true_counts.get(label, 0)}")

    print("\nPredicted:")
    for label in sorted(reverse_label_map):
        print(f"  Class {label} ({reverse_label_map[label]}): {pred_counts.get(label, 0)}")

    print("\nCorrect predictions by class:")
    for label in sorted(reverse_label_map):
        correct = sum(
            (t == label) and (p == label)
            for t, p in zip(y_true, y_pred)
        )
        total = true_counts.get(label, 0)
        print(f"  {reverse_label_map[label]}: {correct}/{total}")

    print("========================================\n")

    # -----------------------------
    # Metrics
    # -----------------------------
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # Create output folder
    os.makedirs(save_dir, exist_ok=True)

    samples = len(y_true)

    metrics = {
        "model_name": model_name,
        "num_samples": len(y_true),
        "ground_truth_distribution": {
            reverse_label_map[k]: true_counts.get(k, 0)
            for k in sorted(reverse_label_map)
        },
        "predicted_distribution": {
            reverse_label_map[k]: pred_counts.get(k, 0)
            for k in sorted(reverse_label_map)
        },
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4)
    }

    # Save as JSON
    output_file = os.path.join(
        save_dir,
        f"{model_name}_metrics.json"
    )

    with open(output_file, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"Results saved to: {output_file}")

    return accuracy, precision, recall, f1, samples
