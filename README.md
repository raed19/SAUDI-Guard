# SAUDI-Guard

**Research implementation of _From Disagreement to Decision: Multi Agent LLM Reasoning for Arabic Mobile Application Security_.**

SAUDI-Guard classifies Arabic-marketplace mobile applications as **Safe** or **Suspicious** using specialized permission, Arabic-review, metadata, and device-risk experts, a disagreement-aware coordination and deliberation stage, and an LLM Security Judge with a deterministic Verifier.

## Repository layout

```text
src/saudi_guard/
  engine.py             Model API adapter and registry
  utils.py              Arabic text processing and evidence utilities
  agents.py             Expert agents and Security Judge
  publishers.py         Publisher-accountability helper
  scenario.py           Main SAUDI-Guard workflow
  ablation_scenario.py  Variant supporting expert and deliberation ablations
  evaluation.py         Classification metrics
scripts/
  run_experiment.py     Command-line experiment runner
  run_ablations.py      All 15 expert subsets or 3 deliberation policies
  evaluate.py           Score saved predictions
paper/manuscript.pdf    Submitted manuscript version
```

## Setup

Requires **Python 3.10+**, access to an LLM API, and an appropriately licensed dataset. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
export OPENAI_API_KEY="YOUR_NEW_KEY"  # Windows PowerShell: $env:OPENAI_API_KEY="YOUR_NEW_KEY"
```

**Security:** API keys were present in the original research notebooks. Revoke/rotate those keys. Never commit `.env`, credentials, private datasets, or raw responses containing sensitive information. `.env.example` is illustrative only; it is not automatically loaded.

## Dataset

Place your authorized input at `data/saudi_guard_dataset.json`. **The dataset is not distributed here.** The original implementation reads a JSON file and converts it to a pandas DataFrame; see `load_dataset()` in `src/saudi_guard/scenario.py` for the precise field assumptions. The paper evaluates **100 applications (50 Safe / 50 Suspicious)**, with VirusTotal-derived labels and Arabic marketplace evidence. The code does not itself collect APKs or reconstruct these labels.

## Run the main framework

```bash
python scripts/run_experiment.py --dataset data/saudi_guard_dataset.json --model gpt-5.1 --output results/main_gpt51.jsonl --num-samples 100
python scripts/evaluate.py --results results/main_gpt51.jsonl --name main_gpt51
```

The script uses `OPENAI_API_KEY` by default. To use another OpenAI-compatible endpoint, pass `--api-base-url URL` and `--api-key-env ENV_VAR`; compatibility depends on the provider and model.

## Cross-backbone evaluation (paper §4.1)

Run the main command separately for each model, changing `--model` and `--output` (and endpoint/key environment variable when appropriate). The paper compares GPT-4.1, GPT-5.1, GPT-5.2, DeepSeek-V4-Pro, and Llama-3.3-70B. **Model identifiers, availability, API compatibility, and provider behavior must be verified before running.** Keep the dataset and configuration constant for fair comparison.

## Expert-subset ablation (paper §4.2)

```bash
python scripts/run_ablations.py --kind experts --dataset data/saudi_guard_dataset.json --model gpt-5.1
```

Runs all **15 non-empty subsets** of the four expert agents using the ablation scenario, with the downstream Judge and Verifier retained as implemented. These are not raw single-agent baselines.

## Deliberation-policy ablation (paper §4.2.1)

```bash
python scripts/run_ablations.py --kind deliberation --dataset data/saudi_guard_dataset.json --model gpt-5.1
```

Compares **none**, **adaptive**, and **always** deliberation using the source notebook's ablation variant. Outputs go to `results/` with separate filenames.

## Evaluation and interpretation

```bash
python scripts/evaluate.py --results results/main_gpt51.jsonl --name main_gpt51
```

The evaluation module reports accuracy, precision, recall and F1 for the **Suspicious** class. Review the output JSONL and metrics before reporting results. The paper's main evaluation reports **87.00% accuracy / 86.87% F1** for GPT-5.1, while its separate deliberation-policy comparison reports **85.00% accuracy / 85.15% F1** for adaptive deliberation. These are different reported experimental results and must **not** be represented as an exact reproduction without checking the original run settings and predictions.

## Reproducibility notes

- Code is refactored from three provided Colab notebooks, not independently reimplemented from the paper.
- LLM calls incur cost; start with `--num-samples 1` to validate the environment.
- The original code has experiment-specific defaults and historical provider assumptions. **The extracted Python modules have been syntax-checked, but not end-to-end tested with the private dataset or live APIs.** Inspect the agent and scenario initialization before large runs.
- LLM versions, sampling settings, input ordering, dataset versions, API responses, and exact experimental configurations can affect reproducibility. Record them alongside every run.
- The manuscript includes further disagreement analysis and raw-expert comparisons; these are described in the paper but are not exposed as standalone CLI workflows in this release.

## Citation

If you use this repository, cite the accompanying manuscript, _From Disagreement to Decision: Multi Agent LLM Reasoning for Arabic Mobile Application Security_. Add final publication metadata and DOI when available.

## License

No open-source license is asserted here. Add a license only after confirming ownership and any third-party code or dataset restrictions.
