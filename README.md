# Phishing Detection & Analysis Tool

A modular, multi-layered cybersecurity software solution designed to ingest, analyze, and score potential phishing threats from URLs, email headers, and file payloads. Built as a university capstone project to provide high-accuracy detection paired with actionable, human-readable explainability.

---

## 🏗️ System Architecture Pipeline

The application processes inputs through a sequential and parallel verification pipeline:

```text
[ User Input ] ──► [ Input Normalizer ] ──┬──► [ Rule Engine (Heuristics) ]
                                          ├──► [ Threat Intel APIs ]
                                          └──► [ ML / AI Engine ]
                                                   │
                                                   ▼
                                         [ Score Fusion & Weights ]
                                                   │
                                                   ▼
                                         [ Explainability Generator ]
                                                   │
                                                   ▼
                                         [ Result & PostgreSQL Log ]
```

---

## 📂 Repository Structure

```text
phishing-detection-tool/
├── docs/                   # Architecture diagrams and documentation (RF-1, RF-2)
├── src/
│   ├── api/                # Application entry point and REST endpoints
│   ├── core/               # Input normalizer (parsing, canonicalization)
│   ├── engines/            # Detection pillars (Rules, Threat Intel, ML)
│   ├── fusion/             # Score aggregation and weighting logic
│   ├── explainability/     # Risk factor and reasoning generator
│   └── database/           # PostgreSQL connection, models, and migrations
├── tests/                  # Unit and integration test suites
├── scripts/                # Utility and database seed scripts
├── .env.example            # Environment variable template
├── requirements.txt        # Python package dependencies
└── README.md               # Project documentation
```

---

## 🛠️ Tech Stack

*   **Language:** Python 
*   **Web Framework:** FastAPI / Flask 
*   **Database & ORM:** PostgreSQL, SQLAlchemy
*   **Analysis:** Regex heuristics, custom feature extraction, third-party threat intelligence integrations.

---

## 🚀 Getting Started

Follow these instructions to set up a local development environment.

### Prerequisites
*   Python 3.10 or higher
*   PostgreSQL installed and running locally or via Docker

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username-here/PlaceHolder-PhishGaurd.git
   cd PlaceHolder-PhishGaurd
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   Copy the example environment file and update it with your local database credentials and API keys:
   ```bash
   cp .env.example .env
   ```

5. **Run the application:**
   ```bash
   python src/api/main.py
   ```

---

## 👥 Team Placeholder

*   **Evgeniy Vodolazov** (Team Lead)
*   **Evan Knieriem** (Backend)
*   **Lucia Martinez-Segundo** (Frontend)
