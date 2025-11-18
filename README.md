# IP Threat Intelligence

AI-powered IP threat detection and analysis system that aggregates threat intelligence data from multiple sources and uses AI/ML to provide intelligent risk assessment and actionable insights.

## Features

- **Multi-Source Threat Intelligence**: Aggregates data from AbuseIPDB, IPQualityScore, and IPAPI
- **AI-Powered Analysis**: Uses Groq LLM (Llama 3) to synthesize threat data and provide risk assessment
- **Smart Caching**: In-memory cache with 5-minute TTL for improved performance
- **RESTful API**: FastAPI-based backend with comprehensive error handling
- **CLI Tool**: Rich terminal interface for easy threat analysis
- **Fallback Logic**: Rule-based analysis when LLM is unavailable

## Tech Stack

- **Backend**: Python + FastAPI
- **AI/ML**: Groq (Llama 3.1-70B)
- **HTTP Client**: httpx (async)
- **CLI**: Click + Rich
- **Testing**: pytest
- **APIs**: AbuseIPDB, IPQualityScore, IPAPI

## Prerequisites

- Python 3.8+
- API Keys:
  - AbuseIPDB API key (get from https://www.abuseipdb.com/)
  - IPQualityScore API key (get from https://www.ipqualityscore.com/)
  - Groq API key (get from https://console.groq.com/)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nkch1k/ThreatDetection.git
cd ThreatDetection
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create `.env` file from example:
```bash
cp .env.example .env
```

5. Add your API keys to `.env`:
```env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
IPQUALITYSCORE_API_KEY=your_ipqualityscore_key_here
GROQ_API_KEY=your_groq_key_here
```

## Usage

### Running the API Server

Start the FastAPI server:
```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

API Documentation: `http://localhost:8000/docs`

### Using the CLI

Analyze an IP address:
```bash
python cli.py --ip 8.8.8.8
```

With custom API URL:
```bash
python cli.py --ip 1.1.1.1 --api-url http://localhost:8000
```

### API Endpoints

#### Analyze IP Address
```bash
GET /api/analyze-ip?ip={ip_address}
```

Example response:
```json
{
  "threat_data": {
    "ip_address": "8.8.8.8",
    "hostname": "dns.google",
    "isp": "Google LLC",
    "country": "United States",
    "abuse_score": 0,
    "recent_reports": 0,
    "vpn_detected": false,
    "proxy_detected": false,
    "fraud_score": 5,
    "is_tor": false
  },
  "ai_analysis": {
    "risk_level": "Low",
    "risk_analysis": "This IP belongs to Google's public DNS service...",
    "recommendations": [
      "Maintain standard security protocols",
      "Continue routine monitoring",
      "No immediate action required"
    ]
  },
  "cached": false,
  "sources_used": ["abuseipdb", "ipqualityscore", "ipapi"]
}
```

#### Health Check
```bash
GET /health
```

#### Cache Statistics
```bash
GET /cache/stats
```

#### Clear Cache
```bash
POST /cache/clear
```

## Testing

Run all tests:
```bash
pytest
```

Run tests with coverage:
```bash
pytest --cov=app tests/
```

Run specific test file:
```bash
pytest tests/test_validators.py
```

## Project Structure

```
ip-threat-intel/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── models.py               # Pydantic models
│   ├── services/
│   │   ├── threat_apis.py      # External API clients
│   │   ├── llm_service.py      # Groq LLM integration
│   │   ├── aggregator.py       # Data aggregation logic
│   │   └── cache.py            # In-memory cache
│   └── utils/
│       └── validators.py       # IP validation
├── tests/
│   ├── test_validators.py
│   ├── test_threat_apis.py
│   └── test_llm_service.py
├── cli.py                      # CLI tool
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── pytest.ini
```

## How It Works

1. **IP Validation**: Validates IPv4 format and rejects private IPs
2. **Cache Check**: Checks for cached results (5-minute TTL)
3. **Data Fetching**: Queries multiple threat intelligence APIs concurrently
4. **Data Aggregation**: Normalizes and combines data from all sources
5. **AI Analysis**: Uses Groq LLM to synthesize threat data and generate risk assessment
6. **Fallback Logic**: If LLM fails, uses rule-based analysis
7. **Caching**: Stores results for improved performance

## Risk Levels

- **Low**: Abuse score < 20, fraud score < 30, no VPN/proxy/Tor, minimal reports
- **Medium**: Abuse score 20-60, fraud score 30-75, VPN/proxy detected, some reports
- **High**: Abuse score > 60, fraud score > 75, Tor detected, many reports
