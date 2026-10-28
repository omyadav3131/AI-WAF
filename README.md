# AI-WAF — AI-Based Web Application Firewall

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.3.0-ee4c2c.svg)](https://pytorch.org/)
[![BERT](https://img.shields.io/badge/Model-BERT-4b8bbe.svg)](https://huggingface.co/bert-base-uncased)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-ff4b4b.svg)](https://streamlit.io/)

AI-WAF is a research prototype that classifies HTTP requests as benign, SQL injection (SQLi), or cross-site scripting (XSS). It uses a fine-tuned BERT model to analyze request text and provides a FastAPI inference service with a Streamlit dashboard.

## The Problem

Traditional web application firewalls often rely on signatures, rules, and pattern matching. Attackers can encode or obfuscate payloads in ways that evade exact string and rule-based checks, while aggressive rules can also block legitimate traffic.

## Our Solution

AI-WAF applies BERT's contextual language representations to HTTP request content. By considering relationships among tokens and their context, the classifier can identify semantic indicators of SQLi and XSS, including payload variations that are difficult to capture with fixed signatures.

## Architecture

```text
HTTP Request
    ↓
Preprocessing
    ↓
BERT Tokenizer
    ↓
BERT Encoder
    ↓
Classification Head
    ↓
Output: BENIGN / SQLi / XSS
    ↓
FastAPI
    ↓
Streamlit Dashboard
```

## Model Results

| Model | Dataset | Macro F1 |
|---|---|---:|
| CNN Baseline | CICIDS 2017 | 0.7332 |
| LSTM Baseline | CICIDS 2017 | 0.6924 |
| BERT v2 | CSIC + Kaggle | 1.0000 |
| BERT v3 | Kaggle Paired | 0.9993 |

BERT v3 fixed the false positive problem that existed in v2.

## Key Research Contributions

- Unified 3-class BERT classifier (BENIGN, SQLi, XSS)
- Paired template training dataset fixing structural bias
- Obfuscation robustness benchmark (max drop 0.16%)
- False positive rate diagnosis and fix
- Token-level attention heatmap for interpretability

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11 |
| Deep learning | PyTorch 2.3.0 |
| NLP framework | HuggingFace Transformers |
| Model architecture | BERT base uncased |
| API | FastAPI |
| ASGI server | Uvicorn |
| Dashboard | Streamlit |
| Training hardware | Kaggle T4 GPU |

## Project Structure

```text
AI-WAF/
├── api/
│   └── app.py
├── datasets/
│   ├── benchmark/
│   ├── processed/       # Excluded from Git
│   └── raw/
├── models/
│   └── bert/
│       ├── tokenizer/
│       ├── tokenizer_v3/
│       ├── model_config_v2.json
│       ├── model_config_v3.json
│       └── README_models.md
├── outputs/
├── scripts/
│   ├── diagnose.py
│   └── test_model.py
├── streamlit/
│   └── streamlit_app.py
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```

Model weights and large raw, processed, and benchmark datasets are not committed. See [models/bert/README_models.md](models/bert/README_models.md) for model download instructions.

## How to Run Locally

1. Clone the repository:

   ```bash
   git clone https://github.com/omyadav3131/AI-WAF.git
   cd AI-WAF
   ```
2. Create and activate a virtual environment with Python 3.11:

   ```bash
   python3.11 -m venv .venv
   # Windows PowerShell: .venv\Scripts\Activate.ps1
   # macOS/Linux: source .venv/bin/activate
   ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. Download the recommended model weights from [Add Google Drive link here].
5. Place `bert_best_v3.pt` in `models/bert/`.
6. Start the API in Terminal 1:

   ```bash
   uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
   ```
7. Start the dashboard in Terminal 2:

   ```bash
   python -m streamlit run streamlit/streamlit_app.py --server.port 8501
   ```
8. Open [http://localhost:8501](http://localhost:8501) in your browser.

## Datasets Used

| Dataset | Use |
|---|---|
| CSIC 2010 | HTTP request data |
| Kaggle SQLi (Syed Saqlain Hussain Shah) | SQL injection examples |
| Kaggle XSS (Syed Saqlain Hussain Shah) | XSS examples |
| CICIDS 2017 | Baseline evaluation |

Dataset files are not included in this repository. Obtain them from their respective sources and follow their licensing and attribution terms.

## About

MCA Research Project — Bharati Vidyapeeth Institute of Management and Information Technology (BVIMIT), Navi Mumbai. Semester 3, Academic Year 2025-26.

**Student:** Om Nandkishor Yadav
