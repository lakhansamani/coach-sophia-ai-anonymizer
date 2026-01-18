# Compliance Guide - Entity Types Reference

## Quick Reference: All Detected Entity Types

This guide provides a comprehensive reference for all PII/PHI entity types detected by the service.

---

## 🏥 HIPAA Protected Health Information (PHI)

### Category 1: Personal Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| PERSON, NAME | Patient, provider, or relative names | "John Smith" | #1 |
| PATIENT_NAME | Specific patient identifier | "Jane Doe" | #1 |

### Category 2: Geographic Information

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| ADDRESS | Street addresses | "123 Main St" | #2 |
| CITY | City names | "Springfield" | #2 |
| STATE | State names | "California" | #2 |
| ZIP_CODE | ZIP codes | "90210" | #2 |
| LOCATION, GPE | General locations | "Boston Medical Center" | #2 |

### Category 3: Temporal Information

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| DATE_OF_BIRTH | Birth dates | "05/15/1980", "DOB: 1980-05-15" | #3 |
| DATE, DATE_TIME | Any dates | "01/15/2024", "2024-01-15" | #3 |
| ADMISSION_DATE | Hospital admission | "Admitted: 03/01/2024" | #3 |
| DISCHARGE_DATE | Hospital discharge | "Discharged: 03/05/2024" | #3 |
| DEATH_DATE | Date of death | "Deceased: 12/01/2023" | #3 |
| TIME | Time information | "10:30 AM" | #3 |

### Category 4: Age Information

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| AGE | General age | "Age: 45", "35 years old" | #4 |
| **AGE_OVER_89** | **Ages >89 (special HIPAA)** | **"Age: 92", "91 years"** | **#4** |

⚠️ **Important**: HIPAA requires special protection for ages over 89!

### Category 5-6: Contact Information

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| PHONE_NUMBER | Phone/fax numbers | "555-123-4567", "(555) 987-6543" | #5 |
| FAX_NUMBER | Fax numbers | "Fax: 555-999-8888" | #5 |
| EMAIL_ADDRESS | Email addresses | "patient@example.com" | #6 |

### Category 7-11: Identification Numbers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| SSN, US_SSN | Social Security Numbers | "123-45-6789" | #7 |
| MEDICAL_RECORD_NUMBER | Medical record numbers | "MRN#12345678" | #8 |
| HEALTH_PLAN_NUMBER | Health plan/insurance numbers | "Insurance#ABC123456" | #9 |
| ACCOUNT_NUMBER | Account numbers | "Account#987654321" | #10 |
| CERTIFICATE_NUMBER | Certificate numbers | "Cert#XYZ789" | #11 |
| LICENSE_NUMBER | License numbers | "License#ABC123" | #11 |
| MEDICAL_LICENSE | Medical license numbers | "MD License: 12345" | #11 |

### Category 12: Vehicle Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| VIN | Vehicle Identification Number | "1HGBH41JXMN109186" | #12 |
| LICENSE_PLATE | License plate numbers | "ABC1234" | #12 |

### Category 13: Device Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| DEVICE_ID | Device identifiers | "Device#ABC123XYZ789" | #13 |
| SERIAL_NUMBER | Serial numbers | "Serial: SN123456789" | #13 |
| IMEI | Mobile device IMEI | "IMEI:123456789012345" | #13 |
| MAC_ADDRESS | MAC addresses | "00:1B:44:11:3A:B7" | #13 |

### Category 14: Web Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| URL | Web URLs | "https://example.com" | #14 |
| IP_ADDRESS | IP addresses | "192.168.1.1" | #14 |

### Category 15: Biometric Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| BIOMETRIC_ID | Biometric identifiers | "Fingerprint#FP123456" | #15 |
| FINGERPRINT | Fingerprint data | "Fingerprint scan: ..." | #15 |
| RETINA_SCAN | Retina/iris scans | "Retina ID: RET123" | #15 |
| FACIAL_RECOGNITION | Facial recognition data | "Face ID: FACE789" | #15 |
| GENETIC_MARKER | DNA/genetic data | "DNA#GEN987654" | #15 |
| DNA_SEQUENCE | DNA sequences | "DNA Sample: ..." | #15 |

### Category 16: Visual Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| PHOTO_ID | Photo identifiers | (Detected via context) | #16 |

### Category 17-18: Unique Identifiers

| Entity Type | Description | Example | HIPAA ID |
|------------|-------------|---------|----------|
| PATIENT_ID | Patient identifiers | "Patient ID: PT123456" | #17 |
| MEMBER_ID | Member identifiers | "Member: MEM789" | #17 |
| PRESCRIPTION_NUMBER | Prescription numbers | "RX#789456123" | #18 |
| NPI_NUMBER | National Provider ID | "NPI: 1234567890" | #18 |
| DEA_NUMBER | DEA numbers | "DEA: AB1234567" | #18 |

---

## 🔐 ISO 27001/27002 - Information Security

### Personal Data Categories

| Category | Entity Types | Examples |
|----------|-------------|----------|
| **Identifiers** | PERSON, NAME, NATIONAL_ID, TAX_ID | "Sarah Jones", "TIN: 12-3456789" |
| **Location Data** | ADDRESS, GPS coordinates | "123 Oak Street", "37.7749°N" |
| **Online Identifiers** | IP_ADDRESS, DEVICE_ID, MAC_ADDRESS | "10.0.0.1", "Device#123" |
| **Physical Characteristics** | Height, weight, blood type | (Context-based detection) |
| **Biometric Data** | FINGERPRINT, DNA, FACIAL_RECOGNITION | "Fingerprint#FP123" |
| **Health Data** | Medical records, diagnoses | "Diagnosis: Type 2 Diabetes" |
| **Demographics** | GENDER, ETHNICITY, RELIGION | "Gender: Female", "Religion: Buddhist" |

### Sensitive Personal Data

| Entity Type | Description | Example |
|------------|-------------|---------|
| GENDER | Gender identity | "Gender: Non-binary", "Sex: Male" |
| ETHNICITY | Ethnic background | "Ethnicity: Hispanic" |
| RACE | Racial information | "Race: Asian" |
| RELIGION | Religious beliefs | "Religion: Christian" |
| SEXUAL_ORIENTATION | Sexual orientation | "Orientation: LGBTQ+" |
| MARITAL_STATUS | Marital status | "Status: Married" |

---

## 💼 SOC 2 - Service Organization Control

### Financial Data (Type II Controls)

| Entity Type | Description | Example |
|------------|-------------|---------|
| CREDIT_CARD | Credit card numbers | "4532-1234-5678-9010" |
| BANK_ACCOUNT | Bank account numbers | "Account: 123456789" |
| IBAN_CODE | International bank account | "GB82 WEST 1234 5698 7654 32" |
| ROUTING_NUMBER | Bank routing numbers | "021000021" |
| SWIFT_CODE | SWIFT/BIC codes | "CHASUS33XXX" |

### Customer Data

| Entity Type | Description | Example |
|------------|-------------|---------|
| PERSON | Customer names | "Alice Johnson" |
| EMAIL_ADDRESS | Customer emails | "customer@company.com" |
| PHONE_NUMBER | Customer phones | "555-0123" |
| ADDRESS | Customer addresses | "456 Business Blvd" |

### Credentials & Access (Security Controls)

| Entity Type | Description | Example |
|------------|-------------|---------|
| API_KEY | API keys | "api_key_abc123def456..." |
| ACCESS_TOKEN | Access tokens | "access_token_xyz789..." |
| SECRET_KEY | Secret keys | "secret_key_secret123..." |
| PASSWORD | Passwords | "Password: MyPass123!" |
| AUTH_TOKEN | Authentication tokens | "Bearer token123abc..." |
| CRYPTO_WALLET | Cryptocurrency wallets | "0x742d35Cc6634C0..." |

---

## 📊 Detection Methods

### Method 1: ML-Based (Primary)

- **Model**: spaCy `en_core_web_lg`
- **Accuracy**: High (0.85-0.99)
- **Entities**: Names, organizations, locations, dates
- **Context**: Uses surrounding text for better accuracy

### Method 2: Custom Recognizers

- **Patterns**: Context-aware regex with keywords
- **Accuracy**: Very High (0.85-0.95)
- **Entities**: DOB, Age >89, MRN, Gender, Device IDs
- **Context**: Uses both pattern and context words

### Method 3: Fallback Regex

- **Patterns**: Strict regex patterns
- **Accuracy**: Medium-High (0.5-0.8)
- **Entities**: All types (30+ patterns)
- **Usage**: Activated when ML fails

---

## 🎯 Confidence Scores

| Score Range | Interpretation | Action |
|-------------|---------------|--------|
| 0.9 - 1.0 | Very High Confidence | Definitely anonymize |
| 0.8 - 0.89 | High Confidence | Anonymize (HIPAA priority) |
| 0.7 - 0.79 | Good Confidence | Anonymize (threshold) |
| 0.5 - 0.69 | Medium Confidence | Anonymize (fallback) |
| < 0.5 | Low Confidence | Manual review recommended |

**Note**: For compliance, we anonymize all detected entities regardless of confidence score.

---

## 🛡️ Special Considerations

### HIPAA-Specific Requirements

1. **Ages over 89**: Must be specially protected (category #4)
2. **All dates**: Any date related to an individual is PHI
3. **Geographic subdivisions**: Smaller than state must be protected
4. **Biometric data**: Includes fingerprints, retina scans, DNA
5. **Unique identifiers**: Any unique number/code related to individual

### ISO 27001 Requirements

1. **Data minimization**: Collect only necessary data
2. **Purpose limitation**: Use data only for stated purpose
3. **Accuracy**: Keep data accurate and up-to-date
4. **Storage limitation**: Delete data when no longer needed
5. **Integrity**: Protect against unauthorized access

### SOC 2 Requirements

1. **Security**: Protect against unauthorized access
2. **Availability**: System available for operation
3. **Processing integrity**: System achieves its purpose
4. **Confidentiality**: Protected as committed/agreed
5. **Privacy**: Personal information collected, used, retained, disclosed

---

## 🔄 Replacement Mapping

| Entity Type | Generic Replacement | Maintains Context? |
|------------|--------------------|--------------------|
| PERSON | "person" | ✅ |
| DATE_OF_BIRTH | "date" | ✅ |
| AGE | "age" | ✅ |
| GENDER | "gender" | ✅ |
| PHONE_NUMBER | "phone" | ✅ |
| EMAIL_ADDRESS | "email" | ✅ |
| MEDICAL_RECORD_NUMBER | "medical_record" | ✅ |
| CREDIT_CARD | "payment" | ✅ |
| SSN | "identifier" | ✅ |
| API_KEY | "credential" | ✅ |

**All replacements maintain sentence structure and readability while removing PII/PHI.**

---

## 📞 Support

For questions about specific entity types or compliance requirements:

- HIPAA: Review 45 CFR §164.514(b)(2)
- ISO 27001: Review ISO/IEC 27001:2013
- SOC 2: Review AICPA Trust Services Criteria

**Last Updated**: 2024
**Version**: 2.0.0
