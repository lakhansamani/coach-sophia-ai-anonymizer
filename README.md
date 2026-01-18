# Presidio Enterprise Anonymization Service

## 🔒 HIPAA, ISO 27001, SOC 2 Compliant PII/PHI Detection & Anonymization

This enterprise-grade service uses Microsoft Presidio with custom recognizers to detect and anonymize sensitive information according to:
- **HIPAA** (Health Insurance Portability and Accountability Act) - All 18 PHI identifiers
- **ISO 27001/27002** (Information Security Management)
- **SOC 2** (Service Organization Control)

### Key Features
✅ **40+ PII/PHI Entity Types** - Comprehensive detection coverage  
✅ **Multi-Layer Detection** - ML-based (spaCy large model) + regex fallback  
✅ **Fail-Safe Compliance** - Never exposes PII even on system failure  
✅ **Graceful Degradation** - Continues with partial failures  
✅ **Pseudonym Preservation** - Protects user-chosen identifiers  
✅ **Production-Ready** - Optimized for Google Cloud Run deployment

## 📋 Compliance Coverage

### HIPAA - All 18 Protected Health Information (PHI) Identifiers

1. ✅ Names (patients, relatives, employers)
2. ✅ Geographic subdivisions smaller than state
3. ✅ Dates (birth, admission, discharge, death)
4. ✅ **Ages over 89** (special HIPAA requirement)
5. ✅ Telephone and fax numbers
6. ✅ Email addresses
7. ✅ Social Security numbers
8. ✅ Medical record numbers
9. ✅ Health plan beneficiary numbers
10. ✅ Account numbers
11. ✅ Certificate/license numbers
12. ✅ Vehicle identifiers (VIN, license plates)
13. ✅ Device identifiers and serial numbers
14. ✅ Web URLs and IP addresses
15. ✅ Biometric identifiers (fingerprints, retina scans)
16. ✅ Full-face photographs
17. ✅ Any unique identifying number
18. ✅ Additional healthcare identifiers (NPI, DEA, prescriptions)

### ISO 27001/27002 - Personal Data Protection

- ✅ Personal identifiers (names, IDs)
- ✅ Location data (addresses, GPS)
- ✅ Online identifiers (IP, device IDs)
- ✅ Physical/physiological characteristics
- ✅ Genetic and biometric data
- ✅ Mental health information
- ✅ Economic, cultural, social identity

### SOC 2 - Confidential Information

- ✅ Personal information (PII)
- ✅ Financial data (credit cards, bank accounts)
- ✅ Health information (PHI)
- ✅ Credentials (API keys, passwords, tokens)
- ✅ Customer data

## 🎯 Detected Entity Types (40+)

### Personal Information
- Names, Date of Birth, Age, Age Over 89
- Gender, Demographics, Ethnicity, Religion
- Marital Status, Sexual Orientation

### Contact Information
- Email Addresses, Phone Numbers, Fax Numbers
- Physical Addresses (Street, City, State, ZIP)
- URLs, IP Addresses

### Financial Information
- Credit Card Numbers
- Bank Account Numbers, IBAN Codes
- Routing Numbers, SWIFT Codes

### Government IDs
- Social Security Numbers (SSN)
- Passport Numbers, Driver License Numbers
- Tax IDs, National IDs

### Medical/Health Identifiers (HIPAA PHI)
- Medical Record Numbers (MRN)
- Health Plan/Insurance Numbers
- Prescription Numbers
- NPI (National Provider Identifier)
- DEA (Drug Enforcement Administration) Numbers
- Medical License Numbers

### Biometric & Physical Data
- Fingerprints, Retina/Iris Scans
- Facial Recognition Data
- DNA/Genetic Markers

### Device & Vehicle Identifiers
- VIN (Vehicle Identification Numbers)
- License Plates
- Device Serial Numbers, IMEI
- MAC Addresses

### Security Credentials (SOC 2)
- API Keys, Access Tokens
- Passwords, Secret Keys
- Authentication Tokens

## Setup

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the service
python main.py
```

Service will run on `http://localhost:8080`

### Docker Deployment (Recommended)

```bash
# Build the image
docker build -t presidio-anonymizer .

# Run locally
docker run -d -p 8080:8080 presidio-anonymizer

# Deploy to Google Cloud Run
gcloud run deploy presidio-anonymizer \
  --image gcr.io/YOUR_PROJECT/presidio-anonymizer \
  --platform managed \
  --region us-central1 \
  --memory 2Gi \
  --timeout 300 \
  --allow-unauthenticated
```

## 🔌 API Endpoints

### GET / - Service Information

Get compliance information and available entity types.

**Response:**
```json
{
  "service": "Presidio Anonymization API",
  "version": "2.0.0",
  "mode": "full_ml",
  "compliance": {
    "standards": ["HIPAA", "ISO 27001", "SOC 2"],
    "features": ["PHI detection", "PII detection", "Fail-safe active"]
  },
  "detected_entity_types": {
    "personal": ["names", "DOB", "age", "gender"],
    "medical": ["MRN", "health plan", "prescription"],
    "financial": ["credit cards", "bank accounts"],
    "credentials": ["API keys", "passwords"]
  }
}
```

### POST /anonymize - Anonymize Text (Compliance-Safe)

**Example 1: Medical Record (HIPAA PHI)**
```json
{
  "text": "Patient: John Smith, DOB: 05/15/1980, Age: 43, Gender: Male, MRN#12345678, Insurance: ABC123456789, Phone: 555-123-4567",
  "language": "en"
}
```

**Response:**
```json
{
  "anonymized_text": "Patient: person, DOB: date, Age: age, Gender: gender, medical_record, health_plan, Phone: phone",
  "anonymized_spans": [
    {"entity_type": "PERSON", "original": "John Smith", "replacement": "person"},
    {"entity_type": "DATE_OF_BIRTH", "original": "05/15/1980", "replacement": "date"},
    {"entity_type": "AGE", "original": "43", "replacement": "age"},
    {"entity_type": "GENDER", "original": "Male", "replacement": "gender"},
    {"entity_type": "MEDICAL_RECORD_NUMBER", "original": "MRN#12345678", "replacement": "medical_record"}
  ],
  "pseudonym_preserved": null
}
```

**Example 2: With Pseudonym Preservation**
```json
{
  "text": "User user123 reported: My SSN is 123-45-6789 and email is john@example.com",
  "pseudonym": "user123",
  "language": "en"
}
```

**Response:**
```json
{
  "anonymized_text": "User user123 reported: My SSN is identifier and email is email",
  "anonymized_spans": [
    {"entity_type": "SSN", "original": "123-45-6789", "replacement": "identifier"},
    {"entity_type": "EMAIL_ADDRESS", "original": "john@example.com", "replacement": "email"}
  ],
  "pseudonym_preserved": "user123"
}
```

**Example 3: Elderly Patient (HIPAA Age > 89)**
```json
{
  "text": "Patient Sarah Johnson, aged 92 years, admitted on 03/15/2024",
  "language": "en"
}
```

**Response:**
```json
{
  "anonymized_text": "Patient person, aged age, admitted on date",
  "anonymized_spans": [
    {"entity_type": "PERSON", "original": "Sarah Johnson", "replacement": "person"},
    {"entity_type": "AGE_OVER_89", "original": "92 years", "replacement": "age"},
    {"entity_type": "DATE", "original": "03/15/2024", "replacement": "date"}
  ]
}
```

### POST /detect - Detect PII/PHI Entities

Detects entities without anonymization for analysis.

**Request:**
```json
{
  "text": "Patient: Emily Chen, DOB: 11/30/1988, SSN: 987-65-4321, Credit Card: 4532-1234-5678-9010",
  "language": "en"
}
```

**Response:**
```json
{
  "entities": [
    {"type": "PERSON", "text": "Emily Chen", "score": 0.95, "method": "ml_model"},
    {"type": "DATE_OF_BIRTH", "text": "11/30/1988", "score": 0.9, "method": "custom_recognizer"},
    {"type": "SSN", "text": "987-65-4321", "score": 0.99, "method": "ml_model"},
    {"type": "CREDIT_CARD", "text": "4532-1234-5678-9010", "score": 0.95, "method": "ml_model"}
  ]
}
```

### GET /health - Health Check

Returns service health and operation mode.

**Response:**
```json
{
  "status": "healthy",
  "ml_analyzer": "active",
  "ml_anonymizer": "active",
  "model": "en_core_web_lg",
  "detection_mode": "ml_based",
  "compliance_mode": "fail_safe_active"
}
```

## 🏗️ Architecture & Features

### Multi-Layer Detection Strategy

1. **Primary Layer**: ML-based detection using spaCy's `en_core_web_lg` model
   - High accuracy NER (Named Entity Recognition)
   - Contextual understanding
   - Custom trained recognizers for HIPAA/ISO/SOC2

2. **Fallback Layer**: Regex-based pattern matching
   - Activates if ML models fail
   - 30+ compliance-focused patterns
   - Ensures service availability

3. **Fail-Safe Layer**: Emergency redaction
   - Ultimate protection against system failures
   - Never exposes PII even in worst-case scenarios

### Compliance-Safe Error Handling

```python
✅ ML model initialization fails → Service starts with regex fallback
✅ Detection fails mid-request → Uses fallback patterns
✅ Anonymizer fails → Uses safe redaction function
✅ Complete system failure → Returns [REDACTED] markers
❌ NEVER returns original text on error
```

## 📊 Generic Noun Replacements

| Entity Type | Replacement | Compliance |
|------------|-------------|------------|
| PERSON, NAME | person | HIPAA #1 |
| DATE_OF_BIRTH, DATE | date | HIPAA #3 |
| AGE, AGE_OVER_89 | age | HIPAA #4 |
| PHONE_NUMBER | phone | HIPAA #5 |
| EMAIL_ADDRESS | email | HIPAA #6 |
| SSN | identifier | HIPAA #7 |
| MEDICAL_RECORD_NUMBER | medical_record | HIPAA #8 |
| HEALTH_PLAN_NUMBER | health_plan | HIPAA #9 |
| ACCOUNT_NUMBER | account | HIPAA #10 |
| LICENSE_NUMBER | license | HIPAA #11 |
| VIN, LICENSE_PLATE | vehicle | HIPAA #12 |
| DEVICE_ID, SERIAL_NUMBER | device | HIPAA #13 |
| URL, IP_ADDRESS | address | HIPAA #14 |
| BIOMETRIC_ID, GENETIC_MARKER | biometric | HIPAA #15 |
| CREDIT_CARD | payment | SOC 2 |
| API_KEY, PASSWORD | credential | SOC 2 |
| GENDER | gender | ISO 27001 |

## 🧪 Testing

Run comprehensive compliance tests:

```bash
# Start the service
python main.py

# In another terminal, run tests
python test_compliance.py
```

The test suite covers:
- ✅ HIPAA PHI (all 18 identifiers)
- ✅ Date of birth and age detection
- ✅ Gender and demographics
- ✅ Financial data (SOC 2)
- ✅ Medical identifiers
- ✅ Biometric data
- ✅ Device and vehicle IDs
- ✅ Credentials and API keys
- ✅ Pseudonym preservation

## 🚀 Google Cloud Run Deployment

```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/YOUR_PROJECT/presidio-anonymizer

# Deploy to Cloud Run
gcloud run deploy presidio-anonymizer \
  --image gcr.io/YOUR_PROJECT/presidio-anonymizer \
  --platform managed \
  --region us-central1 \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300 \
  --max-instances 10 \
  --allow-unauthenticated
```

### Environment Variables

- `PORT` - Server port (automatically set by Cloud Run)
- `PYTHONPATH` - Python module path (automatically configured)

## 📝 Usage Examples

### Python

```python
import requests

# Anonymize medical record
response = requests.post('http://localhost:8080/anonymize', json={
    "text": "Patient John Doe, DOB: 01/15/1990, MRN: MED123456",
    "language": "en"
})

print(response.json()['anonymized_text'])
# Output: "Patient person, DOB: date, MRN: medical_record"
```

### cURL

```bash
curl -X POST http://localhost:8080/anonymize \
  -H "Content-Type: application/json" \
  -d '{
    "text": "SSN: 123-45-6789, Email: user@example.com",
    "language": "en"
  }'
```

### JavaScript/TypeScript

```typescript
const response = await fetch('http://localhost:8080/anonymize', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    text: "Credit Card: 4532-1234-5678-9010",
    language: "en"
  })
});

const data = await response.json();
console.log(data.anonymized_text); // "Credit Card: payment"
```

## 🔐 Security Best Practices

1. **Never log original text** - Always log anonymized versions
2. **Use HTTPS in production** - Encrypt data in transit
3. **Implement rate limiting** - Prevent abuse
4. **Monitor for failures** - Check health endpoint regularly
5. **Regular updates** - Keep dependencies current
6. **Audit trails** - Log all anonymization requests (without PII)

## 📚 Compliance Resources

- [HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
- [ISO 27001 Standard](https://www.iso.org/isoiec-27001-information-security.html)
- [SOC 2 Compliance](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report)

## 🤝 Integration Examples

### With Authentication

```python
# Add authentication header
headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

response = requests.post(
    "https://your-service.run.app/anonymize",
    json={"text": sensitive_text},
    headers=headers
)
```

### Batch Processing

```python
texts = [
    "Patient record 1...",
    "Patient record 2...",
    # ... more records
]

for text in texts:
    result = requests.post(endpoint, json={"text": text})
    anonymized = result.json()['anonymized_text']
    # Store or process anonymized text
```

## 📖 Documentation

- **API Documentation**: Visit `http://localhost:8080/docs` for interactive Swagger UI
- **ReDoc**: Visit `http://localhost:8080/redoc` for alternative documentation

## ⚠️ Important Notes

1. **Ages over 89**: HIPAA requires special handling - automatically detected and anonymized
2. **All dates**: HIPAA considers ALL dates related to an individual as PHI
3. **Biometric data**: Fingerprints, retina scans, DNA are PHI under HIPAA
4. **Device identifiers**: Including VINs, serial numbers, IMEI must be protected
5. **Fail-safe mode**: Service continues operating even if ML models fail

## 📄 License

This service uses Microsoft Presidio (MIT License) and spaCy (MIT License).
