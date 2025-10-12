# System Architecture

## Overall Flow:

[User Input] → [Analysis Module] → [Pre-trained Model] → [Result] → [Beautiful UI Display]
↓               ↓                   ↓                   ↓           ↓
URL/Email    Feature Extraction   Classification    Risk Scoring   Modern Interface

## Components:

### 1. INPUT LAYER
- **URL Input**: Web form, API endpoint, direct input
- **Email Input**: File upload, text paste, email forwarding

### 2. PROCESSING LAYER
- **URL Analyzer**: Extracts 15+ features from URLs
- **Email Analyzer**: Parses headers, body, links, content
- **Feature Engineering**: Converts raw data to model inputs

### 3. AI LAYER  
- **Pre-trained Models**: PhishFish + Community models
- **Ensemble Voting**: Combines multiple model predictions
- **Confidence Scoring**: Probability-based risk assessment

### 4. OUTPUT LAYER
- **Risk Classification**: Safe / Suspicious / Phishing
- **Detailed Report**: Why it was flagged
- **Prevention Actions**: Warnings, blocks, logs
- **Beautiful UI**: Modern, responsive web interface