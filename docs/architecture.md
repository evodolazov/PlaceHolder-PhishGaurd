# PhishGuard Architecture

## Overview

Milestone 0 implements the foundation for URL analysis: validation, normalization, feature extraction, heuristic scoring, explainability, and persistence. The design keeps API concerns separate from core analysis logic and database access.

## Layer responsibilities

- API: owns HTTP request handling and response formatting.
- Services: orchestrates the URL analysis workflow and interacts with persistence.
- Engines: validates and normalizes URLs and extracts deterministic features.
- Fusion: combines low-level indicators into an initial risk score.
- Explainability: structures evidence records so each risk signal has a clear source and description.
- Database: stores the canonical URL and all associated analysis records.

## Future extension points

The current implementation intentionally avoids external network, ML, DNS, TLS, and browser analysis. Those capabilities can be added as additional engines without redesigning the API or repository layer.
