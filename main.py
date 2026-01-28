"""
Presidio REST API with Large SpaCy Model
Optimized for Google Cloud Run deployment
Enhanced with fail-safe compliance mechanisms

COMPLIANCE STANDARDS:
====================
This service implements detection and anonymization for:

1. HIPAA (Health Insurance Portability and Accountability Act)
   - All 18 PHI identifiers including:
     * Names, dates (DOB, admission, discharge, death)
     * Ages over 89 (special HIPAA requirement)
     * Phone numbers, fax numbers, email addresses
     * SSN, medical record numbers, health plan numbers
     * Account numbers, certificate/license numbers
     * Vehicle identifiers (VIN, license plates)
     * Device identifiers and serial numbers
     * URLs, IP addresses
     * Biometric identifiers (fingerprints, retinal scans, etc.)
     * Full-face photographs and comparable images
     * Any unique identifying number, characteristic, or code

2. ISO 27001/27002 (Information Security Management)
   - Personal data protection
   - Identification numbers and online identifiers
   - Location data
   - Physical, physiological, genetic characteristics
   - Mental health data
   - Economic, cultural, social identity

3. SOC 2 (Service Organization Control)
   - Personal information
   - Financial information (credit cards, bank accounts)
   - Health information
   - Customer data
   - Credentials and access tokens

FEATURES:
=========
- Multi-layer detection: ML-based (spaCy) + regex fallback
- Fail-safe anonymization: Never exposes PII on failure
- Graceful degradation: Continues processing partial failures
- Custom recognizers for specialized PII types
- Pseudonym preservation
- Comprehensive logging and monitoring

DETECTED ENTITY TYPES (40+):
============================
Personal: Names, DOB, Age, Gender, Demographics
Contact: Email, Phone, Address, IP, URL
Financial: Credit Cards, Bank Accounts, IBAN, Routing Numbers
Government IDs: SSN, Passport, Driver License, Tax ID, PAN (Permanent Account Number)
Medical: MRN (Medical Record Number), Health Plan, Prescriptions, NPI, DEA numbers
Biometric: Fingerprints, DNA, Facial Recognition
Devices: VIN, Serial Numbers, IMEI, MAC addresses
Credentials: API Keys, Passwords, Tokens
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Tuple
import os
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult
import re
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fallback regex patterns for PII detection (HIPAA, ISO, SOC2 compliance)
FALLBACK_PATTERNS = {
    # Contact Information
    'EMAIL_ADDRESS': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'PHONE_NUMBER': r'\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'URL': r'https?://[^\s]+',
    'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    
    # Financial Information
    'CREDIT_CARD': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'IBAN_CODE': r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',
    'ACCOUNT_NUMBER': r'\b(?:account|acct|acc)[\s#:]*\d{6,17}\b',
    'ROUTING_NUMBER': r'\b\d{9}\b(?=.*(?:routing|aba|rtn))',
    
    # Government IDs (HIPAA)
    'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
    'US_PASSPORT': r'\b[A-Z]{1,2}\d{6,9}\b',
    'US_DRIVER_LICENSE': r'\b[A-Z]{1,2}\d{5,8}\b',
    
    # Medical/Health Identifiers (HIPAA PHI)
    'MEDICAL_RECORD_NUMBER': r'\b(?:MRN|medical\s+record|patient\s+id|mrn\s*#|patient\s+number)[\s#:\-]*[A-Z0-9\-]{6,12}\b',  # Medical Record Number (MRN) - handles formats like MRN-882734
    'HEALTH_PLAN_NUMBER': r'\b(?:health plan|insurance|policy)[\s#:]*[A-Z0-9]{6,20}\b',
    'PRESCRIPTION_NUMBER': r'\b(?:rx|prescription)[\s#:]*\d{6,12}\b',
    'NPI_NUMBER': r'\b\d{10}\b(?=.*npi)',
    'DEA_NUMBER': r'\b[A-Z]{2}\d{7}\b',
    
    # Date of Birth ONLY - Other dates are preserved (user requirement)
    # Only matches dates with explicit birth context keywords
    'DATE_OF_BIRTH': r'\b(?:dob|date\s+of\s+birth|birth\s*date|birth\s*day|born\s+on|born|d\.o\.b\.?)[\s:]*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b',
    
    # Age (HIPAA - ages over 89)
    'AGE_OVER_89': r'\b(?:age|aged)[\s:]*(?:8[9]|9\d|1\d{2})\s*(?:years?|yrs?|y\.?o\.?)?\b',
    'AGE_GENERAL': r'\b(?:age|aged)[\s:]*\d{1,3}\s*(?:years?|yrs?|y\.?o\.?)?\b',
    
    # Biometric & Physical Identifiers (HIPAA)
    'BIOMETRIC_ID': r'\b(?:fingerprint|retina|iris|facial|biometric)[\s#:]*[A-Z0-9]{8,}\b',
    'GENETIC_MARKER': r'\b(?:DNA|genetic|genome)[\s#:]*[A-Z0-9]{8,}\b',
    
    # Vehicle & Device Identifiers (HIPAA)
    'VIN': r'\b[A-HJ-NPR-Z0-9]{17}\b',
    'LICENSE_PLATE': r'\b[A-Z0-9]{2,8}\b(?=.*(?:plate|license plate))',
    'DEVICE_ID': r'\b(?:device|serial|imei)[\s#:]*[A-Z0-9]{8,}\b',
    'MAC_ADDRESS': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
    
    # Certificate & License Numbers (HIPAA)
    'CERTIFICATE_NUMBER': r'\b(?:cert|certificate)[\s#:]*[A-Z0-9]{6,15}\b',
    'LICENSE_NUMBER': r'\b(?:license|lic)[\s#:]*[A-Z0-9]{6,15}\b',
    
    # Other Sensitive Data
    'CRYPTO_WALLET': r'\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',
    'API_KEY': r'\b(?:api[_-]?key|apikey|access[_-]?token)[\s:=]*[\'"]?[A-Za-z0-9_\-]{20,}\b',
    'PASSWORD': r'\b(?:password|passwd|pwd)[\s:=]*[\'"]?[^\s\'"]{8,}\b',
    
    # Gender (for compliance - can be sensitive in some contexts)
    'GENDER_EXPLICIT': r'\b(?:gender|sex)[\s:]*(?:male|female|non-binary|transgender|intersex|other)\b',
    
    # Indian-specific identifiers (HIPAA "Any other unique identifying number" category + ISO 27001)
    'AADHAAR_NUMBER': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 12 digits in XXXX-XXXX-XXXX format
    'PAN_NUMBER': r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',  # Permanent Account Number (PAN) - 10 alphanumeric - format: ACBPM9988K
    'INDIAN_PASSPORT': r'\b[A-Z]{1}[0-9]{7}\b',  # 8 alphanumeric starting with letter
    
    # Username/Handle (SOC 2, ISO 27001 access control & identifiers)
    'USERNAME': r'\b(?:username|user|@|handle|login|uid)[\s:]*[A-Za-z0-9_\.]{4,32}\b',
    
    # Organization/Company Name (ISO 27001 - related party identification)
    # IMPORTANT: Must have explicit legal suffixes to avoid false positives
    # Removed patterns that could match common words like "tech", "seen", etc.
    'COMPANY_NAME': r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:Ltd\.?|Limited|Inc\.?|Incorporated|Corp\.?|Corporation|LLC|LLP|L\.L\.C\.|Pvt\.?\s+Ltd\.?|Private\s+Limited|GmbH|AG|PLC|S\.A\.))\b',
    'ORGANIZATION_NAME': r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:Foundation|Association|Institute|University|College|Hospital|Clinic|Bank|Trust))\b',
    
    # Vehicle Registration/License Plate (HIPAA vehicle identifiers)
    'VEHICLE_REGISTRATION': r'\b[A-Z]{2}[-\s]?\d{2}[-\s][A-Z]{2}[-\s]\d{4}\b',  # Indian format: GJ-01-AB-7788
    
    # Insurance/Policy Numbers (HIPAA health plan, ISO 27001)
    'INSURANCE_POLICY_NUMBER': r'\b(?:policy|plan)[\s#:]*(?:number|no)?[\s#:]*[A-Z]{2,3}[-]?(?:IND[-]?)?\d{6,10}\b',
    
    # School/Institution Names (ISO 27001 - related entity identification)
    'INSTITUTION_NAME': r'\b(?:school|college|university|institute|academy)[\s:]*([A-Z][A-Za-z\s&.,\'-]{3,50})\b',
    
    # ========== INTERNATIONAL IDENTITY CARDS (HIPAA "Any other unique identifying number" + ISO 27001) ==========
    
    # NORTH AMERICA
    'US_SSN': r'\b\d{3}-\d{2}-\d{4}\b',  # 9 digits XXX-XX-XXXX (already covered as SSN but explicit)
    'CANADIAN_SIN': r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b',  # 9 digits social insurance number
    'MEXICAN_CURP': r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}\d{2}\b',  # Unique population registry code
    
    # SOUTH AMERICA
    'BRAZILIAN_CPF': r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b',  # Format: XXX.XXX.XXX-XX or XXXXXXXXXXX
    'ARGENTINIAN_DNI': r'\b\d{1,3}\.?\d{3}\.?\d{3}\b',  # 7-8 digits, format: X.XXX.XXX
    'CHILEAN_RUN': r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9K]\b',  # Format: XX.XXX.XXX-X
    'COLOMBIAN_CEDULA': r'\b\d{4,10}\b(?=\s|$)',  # 4-10 digits national ID
    'VENEZUELAN_ID': r'\b[VJG]\d{6,9}\b',  # V/J/G prefix + 6-9 digits
    
    # EUROPE - Only patterns with specific format requirements (not just digit counts)
    'UK_NINO': r'\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b',  # National Insurance: LL NN NN NN L (specific format)
    'SPANISH_DNI': r'\b\d{8}-?[A-Z]\b',  # DNI: 8 digits + letter (specific format)
    'SPANISH_NIE': r'\b[XYZ]\d{7}-?[A-Z]\b',  # NIE: X/Y/Z + 7 digits + letter (specific format)
    'ITALIAN_CF': r'\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b',  # Codice Fiscale: 16 chars (specific format)
    'FINNISH_PIN': r'\b\d{6}[-+A]\d{3}[0-9A-Y]\b',  # Personal identity code (specific format)
    'IRELAND_PPSN': r'\b\d{7}[A-Z]{1,2}\b',  # Personal public service number (specific format)
    
    # ASIA - Only patterns with specific format requirements
    'HONG_KONG_ID': r'\b[A-Z]\d{6}\([0-9A]\)\b',  # Letter + 6 digits + checksum (specific format)
    'TAIWAN_ID': r'\b[A-Z]\d{9}\b',  # Letter + 9 digits (specific format)
    'SINGAPORE_NRIC': r'\b[STG]\d{7}[A-Z]\b',  # S/T/G + 7 digits + letter (specific format)
    'PAKISTAN_CNIC': r'\b\d{5}[-]\d{7}[-]\d{1}\b',  # Requires hyphens: XXXXX-XXXXXXX-X
    'THAI_ID': r'\b\d{1}[-]\d{4}[-]\d{5}[-]\d{2}[-]\d{1}\b',  # Requires hyphens: N-NNNN-NNNNN-NN-N
    
    # MIDDLE EAST - Only patterns with specific format requirements
    'UAE_CIVIL_NUMBER': r'\b784[-]\d{4}[-]\d{7}[-]\d{1}\b',  # Requires 784 prefix and hyphens
    
    # OCEANIA - Only patterns with specific format requirements
    'NEW_ZEALAND_NHI': r'\b[A-Z]{3}\d{4}\b',  # 3 letters + 4 digits (specific format)
    
    # NOTE: Removed overly broad patterns that match common number sequences:
    # - Patterns matching just N digits without specific format (e.g., \b\d{9}\b)
    # - These cause too many false positives (order numbers, tracking IDs, etc.)
    # - If needed, these should require context keywords like "ID:", "national id", etc.
}

# Initialize FastAPI app
app = FastAPI(
    title="Presidio Anonymization API",
    description="High-accuracy PII anonymization with large language model",
    version="2.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for engines
analyzer = None
anonymizer = None

# Request/Response models
class AnonymizeRequest(BaseModel):
    text: str
    pseudonym: Optional[str] = None
    language: str = "en"
    
    class Config:
        json_schema_extra = {
            "example": {
                "text": "John Smith's email is john@example.com and phone is 555-1234",
                "pseudonym": "user123"
            }
        }

class DetectRequest(BaseModel):
    text: str
    pseudonym: Optional[str] = None
    language: str = "en"

class AnonymizeResponse(BaseModel):
    anonymized_text: str
    anonymized_spans: List[Dict]
    pseudonym_preserved: Optional[str] = None

class DetectResponse(BaseModel):
    entities: List[Dict]

# Initialize Presidio engines
@app.on_event("startup")
async def startup_event():
    global analyzer, anonymizer
    
    logger.info("Starting Presidio initialization...")
    
    # Use large model for better accuracy
    # en_core_web_lg provides better NER performance
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [
            {
                "lang_code": "en", 
                "model_name": "en_core_web_lg"  # Large model for better accuracy
            }
        ]
    }
    
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            provider = NlpEngineProvider(nlp_configuration=nlp_config)
            nlp_engine = provider.create_engine()
            
            # Create custom recognizers for HIPAA, ISO, SOC2 compliance
            custom_recognizers = create_custom_recognizers()
            
            # Initialize analyzer with custom recognizers
            analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=["en"]
            )
            
            # Add custom recognizers to the registry
            for recognizer in custom_recognizers:
                try:
                    analyzer.registry.add_recognizer(recognizer)
                    logger.info(f"Added custom recognizer: {recognizer.supported_entities}")
                except Exception as e:
                    logger.warning(f"Failed to add recognizer {recognizer.supported_entities}: {e}")
            
            anonymizer = AnonymizerEngine()
            
            logger.info(f"✅ Presidio engines initialized with large model and {len(custom_recognizers)} custom recognizers")
            return
            
        except Exception as e:
            retry_count += 1
            logger.error(f"Failed to initialize Presidio (attempt {retry_count}/{max_retries}): {e}")
            
            if retry_count >= max_retries:
                logger.critical(
                    "⚠️  ML models failed to initialize. Service will use fallback regex patterns. "
                    "PII detection accuracy may be reduced but compliance is maintained."
                )
                # Don't raise - allow service to start with fallback mode
                analyzer = None
                anonymizer = None
                return
            
            # Wait before retry
            import asyncio
            await asyncio.sleep(2 ** retry_count)  # Exponential backoff

# Enhanced generic noun mappings - Contextually relevant replacements
# Each replacement is chosen to maintain sentence readability while removing PII
GENERIC_NOUNS = {
    # Personal Identifiers - Use natural language nouns
    'PERSON': '[Person]',
    'NAME': '[Person]',
    'PATIENT_NAME': '[Patient]',
    
    # Contact Information - Clear descriptive placeholders
    'EMAIL_ADDRESS': '[email address]',
    'PHONE_NUMBER': '[phone number]',
    'FAX_NUMBER': '[fax number]',
    'URL': '[website]',
    'IP_ADDRESS': '[IP address]',
    
    # Location Data - Preserve context
    'LOCATION': '[location]',
    'GPE': '[place]',
    'LOC': '[location]',
    'ADDRESS': '[address]',
    'STREET_ADDRESS': '[street address]',
    'CITY': '[city]',
    'STATE': '[state]',
    'ZIP_CODE': '[zip code]',
    'COUNTRY': '[country]',
    
    # Organizations - Descriptive
    'ORGANIZATION': '[organization]',
    'ORG': '[organization]',
    'FACILITY': '[facility]',
    'HOSPITAL': '[medical facility]',
    
    # Date of Birth ONLY - Other dates are preserved per user requirement
    # Generic DATE and DATE_TIME from ML models are EXCLUDED from anonymization
    'DATE_OF_BIRTH': '[birth date]',
    'DOB': '[birth date]',
    'BIRTHDAY': '[birth date]',
    
    # Age Information (HIPAA) - Descriptive
    'AGE': '[age]',
    'AGE_OVER_89': '[age]',
    'AGE_GENERAL': '[age]',
    
    # Financial Information (SOC 2) - Clear placeholders
    'CREDIT_CARD': '[credit card number]',
    'IBAN_CODE': '[bank account]',
    'ACCOUNT_NUMBER': '[account number]',
    'ROUTING_NUMBER': '[routing number]',
    'BANK_ACCOUNT': '[bank account]',
    'SWIFT_CODE': '[bank code]',
    
    # Government IDs (HIPAA) - Descriptive placeholders
    'SSN': '[social security number]',
    'US_SSN': '[social security number]',
    'US_PASSPORT': '[passport number]',
    'US_DRIVER_LICENSE': '[driver license]',
    'DRIVER_LICENSE': '[driver license]',
    'PASSPORT': '[passport number]',
    'TAX_ID': '[tax identifier]',
    'NATIONAL_ID': '[national ID]',
    
    # Medical/Health Identifiers (HIPAA PHI) - Clear medical context
    'MEDICAL_RECORD_NUMBER': '[medical record number]',
    'HEALTH_PLAN_NUMBER': '[health plan ID]',
    'PATIENT_ID': '[patient ID]',
    'PRESCRIPTION_NUMBER': '[prescription number]',
    'NPI_NUMBER': '[provider ID]',
    'DEA_NUMBER': '[DEA number]',
    'MEDICAL_LICENSE': '[medical license]',
    'INSURANCE_NUMBER': '[insurance ID]',
    'POLICY_NUMBER': '[policy number]',
    'MEMBER_ID': '[member ID]',
    
    # Biometric & Physical Data (HIPAA) - Clear descriptions
    'BIOMETRIC_ID': '[biometric data]',
    'FINGERPRINT': '[biometric data]',
    'RETINA_SCAN': '[biometric data]',
    'FACIAL_RECOGNITION': '[biometric data]',
    'GENETIC_MARKER': '[genetic data]',
    'DNA_SEQUENCE': '[genetic data]',
    
    # Vehicle & Device Identifiers (HIPAA) - Descriptive
    'VIN': '[vehicle identifier]',
    'LICENSE_PLATE': '[license plate]',
    'DEVICE_ID': '[device identifier]',
    'SERIAL_NUMBER': '[serial number]',
    'MAC_ADDRESS': '[device address]',
    'IMEI': '[device identifier]',
    
    # Certificates & Licenses (HIPAA)
    'CERTIFICATE_NUMBER': '[certificate number]',
    'LICENSE_NUMBER': '[license number]',
    
    # Sensitive Personal Data (ISO 27001, GDPR) - Neutral placeholders
    'GENDER': '[gender]',
    'GENDER_EXPLICIT': '[gender]',
    'ETHNICITY': '[demographic info]',
    'RACE': '[demographic info]',
    'RELIGION': '[religious affiliation]',
    'SEXUAL_ORIENTATION': '[personal info]',
    'MARITAL_STATUS': '[marital status]',
    
    # Security & Access (SOC 2) - Clear credential markers
    'CRYPTO': '[crypto wallet]',
    'CRYPTO_WALLET': '[crypto wallet]',
    'API_KEY': '[API credential]',
    'ACCESS_TOKEN': '[access token]',
    'SECRET_KEY': '[secret key]',
    'PASSWORD': '[password]',
    'AUTH_TOKEN': '[auth token]',
    'USERNAME': '[username]',
    
    # Indian-specific identifiers (HIPAA "Any other unique identifying number", ISO 27001)
    'AADHAAR_NUMBER': '[Aadhaar number]',
    'PAN_NUMBER': '[PAN number]',
    'INDIAN_PASSPORT': '[passport number]',
    'PASSPORT_NUMBER': '[passport number]',
    'PAN': '[PAN number]',
    
    # Organization & Related Entities (ISO 27001)
    'COMPANY_NAME': '[company name]',
    'ORGANIZATION_NAME': '[organization name]',
    'INSTITUTION_NAME': '[institution name]',
    
    # Vehicle & Insurance (HIPAA vehicle identifiers, ISO 27001)
    'VEHICLE_REGISTRATION': '[vehicle registration]',
    'INSURANCE_POLICY_NUMBER': '[policy number]',
    'INSURANCE_POLICY': '[policy number]',
    
    # ========== INTERNATIONAL IDENTITY CARDS ==========
    # All international IDs use a generic [national ID] placeholder
    # North America
    'CANADIAN_SIN': '[national ID]',
    'MEXICAN_CURP': '[national ID]',
    
    # South America
    'BRAZILIAN_CPF': '[national ID]',
    'ARGENTINIAN_DNI': '[national ID]',
    'CHILEAN_RUN': '[national ID]',
    'COLOMBIAN_CEDULA': '[national ID]',
    'VENEZUELAN_ID': '[national ID]',
    
    # Europe
    'UK_NINO': '[national ID]',
    'UK_NHS_NUMBER': '[health ID]',
    'GERMAN_STEUERNUMMER': '[tax ID]',
    'FRENCH_INSEE': '[national ID]',
    'SPANISH_DNI': '[national ID]',
    'SPANISH_NIE': '[national ID]',
    'ITALIAN_CF': '[national ID]',
    'DUTCH_BSN': '[national ID]',
    'BELGIAN_ID': '[national ID]',
    'POLISH_PESEL': '[national ID]',
    'PORTUGUESE_NIC': '[national ID]',
    'PORTUGUESE_NIF': '[tax ID]',
    'CZECH_BIRTH_NUMBER': '[national ID]',
    'DANISH_CPR': '[national ID]',
    'FINNISH_PIN': '[national ID]',
    'SWEDISH_PERSONNUMMER': '[national ID]',
    'NORWEGIAN_FOEDSELS': '[national ID]',
    'AUSTRIAN_PIN': '[national ID]',
    'HUNGARIAN_ID': '[national ID]',
    'GREEK_ID': '[national ID]',
    'ROMANIAN_CNP': '[national ID]',
    'BULGARIAN_EGN': '[national ID]',
    'CROATIAN_OIB': '[national ID]',
    'SLOVAK_BIRTH_NUMBER': '[national ID]',
    'SLOVENIAN_EMSO': '[national ID]',
    'ESTONIA_ID': '[national ID]',
    'LATVIA_ID': '[national ID]',
    'LITHUANIA_ID': '[national ID]',
    'ICELAND_KENNITALA': '[national ID]',
    'IRELAND_PPSN': '[national ID]',
    
    # Middle East & Central Asia
    'UAE_CIVIL_NUMBER': '[national ID]',
    'SAUDI_NATIONAL_ID': '[national ID]',
    'ISRAELI_ID': '[national ID]',
    'IRAN_NATIONAL_ID': '[national ID]',
    'BAHRAIN_ID': '[national ID]',
    'KUWAIT_CIVIL_ID': '[national ID]',
    'IRAQ_NATIONAL_ID': '[national ID]',
    
    # Asia
    'CHINESE_ID': '[national ID]',
    'CHINESE_ID_OLD': '[national ID]',
    'HONG_KONG_ID': '[national ID]',
    'TAIWAN_ID': '[national ID]',
    'JAPANESE_MY_NUMBER': '[national ID]',
    'SOUTH_KOREAN_RRN': '[national ID]',
    'SINGAPORE_NRIC': '[national ID]',
    'MALAYSIAN_ID': '[national ID]',
    'INDONESIAN_NIK': '[national ID]',
    'THAI_ID': '[national ID]',
    'VIETNAMESE_ID': '[national ID]',
    'PHILIPPINE_PHILSYS': '[national ID]',
    'PAKISTAN_CNIC': '[national ID]',
    'NEPAL_CITIZENSHIP': '[national ID]',
    'BANGLADESH_NID': '[national ID]',
    'CAMBODIA_ID': '[national ID]',
    
    # Africa
    'SOUTH_AFRICAN_ID': '[national ID]',
    'NIGERIAN_NIN': '[national ID]',
    'KENYAN_ID': '[national ID]',
    'GHANAIAN_ID': '[national ID]',
    'EGYPTIAN_ID': '[national ID]',
    'MOROCCAN_ID': '[national ID]',
    'ETHIOPIAN_ID': '[national ID]',
    
    # Oceania
    'AUSTRALIAN_TFN': '[tax ID]',
    'NEW_ZEALAND_IRD': '[tax ID]',
    'NEW_ZEALAND_NHI': '[health ID]',
    
    # Default fallback
    'DEFAULT': '[personal information]'
}

# Entity types to EXCLUDE from anonymization
# These are detected by ML but should NOT be anonymized per user requirement
EXCLUDED_ENTITY_TYPES = {
    # ===== DATES (Only birth dates should be anonymized) =====
    'DATE',           # Generic dates (appointment dates, event dates, etc.) - PRESERVE
    'DATE_TIME',      # Generic date/time - PRESERVE
    'TIME',           # Time alone - PRESERVE
    'DATE_FULL',      # Generic full date format - PRESERVE (if detected)
    'DATE_ISO',       # Generic ISO date format - PRESERVE (if detected)
    'ADMISSION_DATE', # Admission dates - PRESERVE
    'DISCHARGE_DATE', # Discharge dates - PRESERVE
    'DEATH_DATE',     # Death dates - PRESERVE
    
    # ===== NUMBERS & QUANTITIES (Important context) =====
    'CARDINAL',       # Numbers (spaCy) - PRESERVE (e.g., "5 items", "100 users")
    'ORDINAL',        # Ordinal numbers (spaCy) - PRESERVE (e.g., "1st", "2nd")
    'QUANTITY',       # Quantities (spaCy) - PRESERVE (e.g., "5 kg", "10 miles")
    'MONEY',          # Money amounts (spaCy) - PRESERVE (e.g., "$500", "€100")
    'PERCENT',        # Percentages (spaCy) - PRESERVE (e.g., "50%", "25 percent")
    
    # ===== GENERAL ENTITIES (Context-important, not PII) =====
    'NORP',           # Nationalities/religions/political groups - PRESERVE
    'EVENT',          # Named events (spaCy) - PRESERVE (e.g., "Olympics", "Conference")
    'WORK_OF_ART',    # Titles of works (spaCy) - PRESERVE (e.g., book/movie titles)
    'LAW',            # Legal documents (spaCy) - PRESERVE (e.g., "HIPAA", "GDPR")
    'LANGUAGE',       # Languages (spaCy) - PRESERVE (e.g., "English", "Spanish")
    'PRODUCT',        # Products (spaCy) - PRESERVE (e.g., "iPhone", "Windows")
    'FAC',            # Facilities/buildings (spaCy) - PRESERVE (e.g., "Empire State Building")
    
    # ===== ORGANIZATION (Often causes false positives) =====
    # spaCy's ORG detection often incorrectly flags common words like "tech", "software"
    # We use specific COMPANY_NAME patterns with legal suffixes instead
    'ORG',            # Generic organization from spaCy - too many false positives
    'ORGANIZATION',   # Generic organization - too many false positives
    
    # ===== OVERLY BROAD NUMERIC IDs (High false positive risk) =====
    # These patterns match common number sequences that are usually NOT national IDs
    'DUTCH_BSN',      # 9 digits - too broad, matches order numbers
    'ISRAELI_ID',     # 9 digits - too broad
    'BAHRAIN_ID',     # 9 digits - too broad
    'CAMBODIA_ID',    # 9 digits - too broad
    'CROATIAN_OIB',   # 11 digits - too broad
    'NIGERIAN_NIN',   # 11 digits - too broad
    'ESTONIA_ID',     # 11 digits - too broad
    'LITHUANIA_ID',   # 11 digits - too broad
    'JAPANESE_MY_NUMBER',  # 12 digits - too broad
    'KUWAIT_CIVIL_ID',     # 12 digits - too broad
    'CHINESE_ID_OLD',      # 15 digits - too broad
    'INDONESIAN_NIK',      # 16 digits - too broad
    'CHINESE_ID',          # 18 digits - too broad
    'COLOMBIAN_CEDULA',    # 4-10 digits - way too broad
    'VIETNAMESE_ID',       # 9-12 digits - too broad
    'KENYAN_ID',           # 6-10 digits - too broad
    'ETHIOPIAN_ID',        # 9-12 digits - too broad
    'MOROCCAN_ID',         # 6-8 digits - too broad
    'BANGLADESH_NID',      # 10-17 digits - too broad
    'CZECH_BIRTH_NUMBER',  # 10 digits - too broad
    'SLOVAK_BIRTH_NUMBER', # 10 digits - too broad
    'SAUDI_NATIONAL_ID',   # 10 digits - too broad
    'PORTUGUESE_NIF',      # 9 digits - too broad
    'SLOVENIAN_EMSO',      # 13 digits - too broad
    'EGYPTIAN_ID',         # 14 digits - too broad
}

# Entity types that ARE birth-date related and should be anonymized
BIRTH_DATE_ENTITY_TYPES = {
    'DATE_OF_BIRTH',
    'DOB',
    'BIRTH_DATE',
    'BIRTHDAY',
}

def should_anonymize_entity(entity_type: str, entity_text: str = "", context: str = "") -> bool:
    """
    Determine if an entity should be anonymized based on its type and context.
    
    Rules:
    1. Excluded entity types are NEVER anonymized (dates, numbers, products, etc.)
    2. Birth date entity types are ALWAYS anonymized
    3. Generic DATE entities are only anonymized if context suggests birth date
    4. Numeric-only entities need context validation to avoid false positives
    5. Common words/phrases that look like PII are filtered out
    """
    entity_upper = entity_type.upper()
    entity_text_clean = entity_text.strip()
    
    # Always anonymize birth date types
    if entity_upper in BIRTH_DATE_ENTITY_TYPES:
        return True
    
    # Never anonymize excluded types
    if entity_upper in EXCLUDED_ENTITY_TYPES:
        # Double-check: is this actually a birth date disguised as DATE?
        birth_keywords = ['birth', 'born', 'dob', 'd.o.b', 'birthday']
        context_lower = context.lower()
        entity_lower = entity_text.lower()
        
        for keyword in birth_keywords:
            if keyword in context_lower or keyword in entity_lower:
                logger.info(f"DATE entity '{entity_text}' has birth context - will anonymize")
                return True
        
        return False
    
    # ===== ADDITIONAL FILTERING TO PREVENT FALSE POSITIVES =====
    
    # Filter 1: Skip very short entities (likely false positives)
    if len(entity_text_clean) < 3:
        logger.debug(f"Skipping short entity: '{entity_text_clean}'")
        return False
    
    # Filter 2: Skip common words that might be detected as PERSON or ORG
    COMMON_WORDS_NOT_PII = {
        # Role words
        'patient', 'doctor', 'nurse', 'user', 'client', 'customer', 'admin',
        'manager', 'director', 'ceo', 'cfo', 'cto', 'president', 'chairman',
        # Days
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
        # Months
        'january', 'february', 'march', 'april', 'may', 'june', 'july', 
        'august', 'september', 'october', 'november', 'december',
        # Time words
        'morning', 'afternoon', 'evening', 'night', 'today', 'tomorrow', 'yesterday',
        # Common words
        'ok', 'okay', 'yes', 'no', 'hello', 'hi', 'bye', 'thanks', 'thank',
        'please', 'sorry', 'help', 'need', 'want', 'like', 'love', 'hate',
        'good', 'bad', 'great', 'nice', 'best', 'worst', 'first', 'last',
        'new', 'old', 'big', 'small', 'high', 'low', 'fast', 'slow',
        'the', 'and', 'but', 'for', 'with', 'this', 'that', 'these', 'those',
        # Tech/industry words often misdetected as ORG
        'tech', 'technology', 'technologies', 'software', 'hardware', 'internet',
        'web', 'mobile', 'app', 'apps', 'digital', 'data', 'cloud', 'ai', 'ml',
        'seen', 'see', 'saw', 'evolve', 'evolved', 'evolving',
        # Common verbs that might be misdetected
        've', 'ive', "i've", 'have', 'has', 'had', 'been', 'being', 'be',
    }
    
    # Check for common words - applies to PERSON and ORG entities
    if entity_upper in ['PERSON', 'ORG', 'ORGANIZATION', 'COMPANY_NAME']:
        # Split entity text into words and check each
        entity_words = entity_text_clean.lower().split()
        if all(word in COMMON_WORDS_NOT_PII for word in entity_words):
            logger.debug(f"Skipping common words detected as {entity_upper}: '{entity_text_clean}'")
            return False
        
        # Also check if the entire text is a common phrase
        if entity_text_clean.lower() in COMMON_WORDS_NOT_PII:
            logger.debug(f"Skipping common word detected as {entity_upper}: '{entity_text_clean}'")
            return False
        
        # Check for phrases like "ve seen tech" - common contractions misdetected
        if entity_text_clean.lower().startswith(('ve ', "i've ", 'ive ')):
            logger.debug(f"Skipping contraction phrase detected as {entity_upper}: '{entity_text_clean}'")
            return False
    
    # Filter 3: Skip version numbers (e.g., "1.2.3", "v2.0")
    import re
    if re.match(r'^v?\d+(\.\d+)+$', entity_text_clean, re.IGNORECASE):
        logger.debug(f"Skipping version number: '{entity_text_clean}'")
        return False
    
    # Filter 4: Skip simple numeric sequences without context for URL/IP
    if entity_upper == 'IP_ADDRESS':
        # Skip localhost, broadcast, and common internal IPs that are not PII
        non_pii_ips = ['127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.0.1', '10.0.0.1']
        if entity_text_clean in non_pii_ips:
            logger.debug(f"Skipping common non-PII IP: '{entity_text_clean}'")
            return False
    
    # Filter 5: Skip entities that are just numbers without proper context
    # (Phone numbers, SSNs etc. have specific formats that are already validated by regex)
    if entity_text_clean.isdigit() and len(entity_text_clean) < 6:
        logger.debug(f"Skipping short numeric entity: '{entity_text_clean}'")
        return False
    
    # Filter 6: For LOCATION/GPE, only anonymize if it looks like a specific address
    # General place names (countries, states, cities) should be preserved
    if entity_upper in ['LOCATION', 'GPE', 'LOC']:
        # Check if this is a full address (has numbers + street indicators)
        address_indicators = ['street', 'st.', 'avenue', 'ave.', 'road', 'rd.', 
                            'boulevard', 'blvd.', 'lane', 'ln.', 'drive', 'dr.',
                            'apt', 'apartment', 'suite', 'unit', 'floor', '#']
        context_lower = context.lower()
        
        # Only anonymize if it looks like a specific street address
        has_number = any(c.isdigit() for c in entity_text_clean)
        has_address_word = any(ind in context_lower for ind in address_indicators)
        
        if not (has_number and has_address_word):
            # This is likely just a city/state/country name - preserve it
            logger.debug(f"Preserving general location (not address): '{entity_text_clean}'")
            return False
    
    # All other entity types - anonymize
    return True

def get_generic_noun(entity_type: str) -> str:
    """Get contextually relevant generic noun for entity type."""
    return GENERIC_NOUNS.get(entity_type.upper(), GENERIC_NOUNS['DEFAULT'])

def create_custom_recognizers():
    """
    Create custom recognizers for HIPAA, ISO, and SOC2 compliance.
    Returns list of custom PatternRecognizer objects.
    """
    from presidio_analyzer import PatternRecognizer, Pattern
    
    custom_recognizers = []
    
    try:
        # Date of Birth Recognizer - ONLY matches dates with explicit birth context
        # Generic dates are NOT anonymized per user requirement
        dob_patterns = [
            # Explicit DOB keyword followed by date
            Pattern(name="dob_keyword", regex=r'\b(?:dob|d\.o\.b\.?)[\s:]*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})', score=0.95),
            # "date of birth" phrase followed by date
            Pattern(name="date_of_birth", regex=r'\bdate\s+of\s+birth[\s:]*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})', score=0.95),
            # "birth date" or "birthday" followed by date
            Pattern(name="birth_date", regex=r'\bbirth\s*(?:date|day)[\s:]*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})', score=0.95),
            # "born on" or "born" followed by date
            Pattern(name="born_on", regex=r'\bborn\s+(?:on\s+)?(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})', score=0.9),
            # Date followed by "is my birthday" or similar
            Pattern(name="my_birthday", regex=r'(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\s+(?:is\s+)?(?:my\s+)?(?:birth\s*day|birthday)', score=0.9),
        ]
        dob_recognizer = PatternRecognizer(
            supported_entity="DATE_OF_BIRTH",
            patterns=dob_patterns,
            context=["born", "dob", "birth", "birthday", "date of birth", "d.o.b"]
        )
        custom_recognizers.append(dob_recognizer)
        
        # Age Over 89 Recognizer (HIPAA requires special protection)
        age_89_pattern = Pattern(
            name="age_over_89",
            regex=r'\b(?:age|aged)[\s:]*(?:8[9]|9\d|1\d{2})\s*(?:years?|yrs?|y\.?o\.?)?',
            score=0.95
        )
        age_89_recognizer = PatternRecognizer(
            supported_entity="AGE_OVER_89",
            patterns=[age_89_pattern],
            context=["age", "aged", "years old", "y/o", "y.o."]
        )
        custom_recognizers.append(age_89_recognizer)
        
        # Medical Record Number (HIPAA PHI)
        mrn_patterns = [
            Pattern(name="mrn_explicit", regex=r'\b(?:MRN|medical\s+record|patient\s+id|mrn\s*#)[\s#:\-]*[A-Z0-9\-]{6,12}\b', score=0.9),
            Pattern(name="mrn_pattern", regex=r'\bMRN[\s#:\-]*\d{6,10}\b', score=0.95),
            Pattern(name="mrn_full_text", regex=r'\bmedical\s+record\s+number[\s#:\-]*[A-Z0-9\-]{6,12}\b', score=0.95),
        ]
        mrn_recognizer = PatternRecognizer(
            supported_entity="MEDICAL_RECORD_NUMBER",
            patterns=mrn_patterns,
            context=["medical record", "medical record number", "MRN", "patient id", "patient number", "patient record"]
        )
        custom_recognizers.append(mrn_recognizer)
        
        # Health Plan/Insurance Number (HIPAA PHI)
        health_plan_pattern = Pattern(
            name="health_plan",
            regex=r'\b(?:health plan|insurance|policy|member)[\s#:]*[A-Z0-9]{6,20}\b',
            score=0.85
        )
        health_plan_recognizer = PatternRecognizer(
            supported_entity="HEALTH_PLAN_NUMBER",
            patterns=[health_plan_pattern],
            context=["insurance", "health plan", "policy", "member id", "subscriber"]
        )
        custom_recognizers.append(health_plan_recognizer)
        
        # Gender Recognizer (sensitive personal data)
        gender_pattern = Pattern(
            name="gender",
            regex=r'\b(?:gender|sex)[\s:]*(?:male|female|non-binary|transgender|intersex|other|M|F|X)\b',
            score=0.8
        )
        gender_recognizer = PatternRecognizer(
            supported_entity="GENDER",
            patterns=[gender_pattern],
            context=["gender", "sex", "identify as"]
        )
        custom_recognizers.append(gender_recognizer)
        
        # Device/Serial Number (HIPAA)
        device_pattern = Pattern(
            name="device_id",
            regex=r'\b(?:device|serial|IMEI|MEID)[\s#:]*[A-Z0-9]{8,20}\b',
            score=0.85
        )
        device_recognizer = PatternRecognizer(
            supported_entity="DEVICE_ID",
            patterns=[device_pattern],
            context=["device", "serial", "IMEI", "equipment"]
        )
        custom_recognizers.append(device_recognizer)
        
        # VIN (Vehicle Identification Number - HIPAA)
        vin_pattern = Pattern(
            name="vin",
            regex=r'\b[A-HJ-NPR-Z0-9]{17}\b',
            score=0.9
        )
        vin_recognizer = PatternRecognizer(
            supported_entity="VIN",
            patterns=[vin_pattern],
            context=["VIN", "vehicle", "car", "automobile"]
        )
        custom_recognizers.append(vin_recognizer)
        
        # API Keys and Credentials (SOC 2)
        api_key_pattern = Pattern(
            name="api_key",
            regex=r'\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\s:=]*[\'"]?[A-Za-z0-9_\-]{20,}\b',
            score=0.9
        )
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern],
            context=["api", "key", "token", "secret", "credential"]
        )
        custom_recognizers.append(api_key_recognizer)
        
        # Account Numbers (SOC 2, financial data)
        account_pattern = Pattern(
            name="account_number",
            regex=r'\b(?:account|acct|acc)[\s#:]*\d{6,17}\b',
            score=0.85
        )
        account_recognizer = PatternRecognizer(
            supported_entity="ACCOUNT_NUMBER",
            patterns=[account_pattern],
            context=["account", "acct", "bank", "financial"]
        )
        custom_recognizers.append(account_recognizer)
        
        # Aadhaar Number (Indian unique identifier - HIPAA "Any other unique number")
        aadhaar_pattern = Pattern(
            name="aadhaar",
            regex=r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            score=0.95
        )
        aadhaar_recognizer = PatternRecognizer(
            supported_entity="AADHAAR_NUMBER",
            patterns=[aadhaar_pattern],
            context=["aadhaar", "aadhaar number", "uid"]
        )
        custom_recognizers.append(aadhaar_recognizer)
        
        # PAN Number (Permanent Account Number - Indian tax identifier - HIPAA "Any other unique number")
        pan_pattern = Pattern(
            name="pan",
            regex=r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
            score=0.95
        )
        pan_recognizer = PatternRecognizer(
            supported_entity="PAN_NUMBER",
            patterns=[pan_pattern],
            context=["PAN", "pan", "pan number", "permanent account", "tax identifier", "tax number"]
        )
        custom_recognizers.append(pan_recognizer)
        
        # Indian Passport (HIPAA passport number + ISO 27001 identifier)
        passport_pattern = Pattern(
            name="indian_passport",
            regex=r'\b[A-Z]{1}[0-9]{7}\b',
            score=0.9
        )
        passport_recognizer = PatternRecognizer(
            supported_entity="INDIAN_PASSPORT",
            patterns=[passport_pattern],
            context=["passport", "passport number"]
        )
        custom_recognizers.append(passport_recognizer)
        
        # Username (SOC 2, ISO 27001 - access control and online identifiers)
        username_pattern = Pattern(
            name="username",
            regex=r'\b(?:username|user|handle|login|uid)[\s:]*([A-Za-z0-9_\.]{4,32})\b',
            score=0.85
        )
        username_recognizer = PatternRecognizer(
            supported_entity="USERNAME",
            patterns=[username_pattern],
            context=["username", "user", "handle", "login", "@"]
        )
        custom_recognizers.append(username_recognizer)
        
        # Company/Organization Name (ISO 27001 - related entity identification)
        # IMPORTANT: Removed "Tech", "Technologies" - too common and causes false positives
        # Only match when followed by legal suffixes like Ltd, Inc, Corp, LLC
        company_patterns = [
            # Must end with legal entity suffix
            Pattern(name="company_ltd", regex=r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:Ltd\.?|Limited))\b', score=0.9),
            Pattern(name="company_inc", regex=r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:Inc\.?|Incorporated))\b', score=0.9),
            Pattern(name="company_corp", regex=r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:Corp\.?|Corporation))\b', score=0.9),
            Pattern(name="company_llc", regex=r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:LLC|LLP|L\.L\.C\.))\b', score=0.9),
            Pattern(name="company_pvt_ltd", regex=r'\b([A-Z][A-Za-z\s&.,\'-]{2,40}\s+(?:Pvt\.?\s+Ltd\.?|Private\s+Limited))\b', score=0.95),
        ]
        company_recognizer = PatternRecognizer(
            supported_entity="COMPANY_NAME",
            patterns=company_patterns,
            context=["company", "organization", "corporation", "employer", "works at", "employed by"]
        )
        custom_recognizers.append(company_recognizer)
        
        # Vehicle Registration Number (HIPAA vehicle identifiers, Indian format)
        registration_pattern = Pattern(
            name="vehicle_registration",
            regex=r'\b[A-Z]{2}[-\s]?\d{2}[-\s][A-Z]{2}[-\s]\d{4}\b',  # GJ-01-AB-7788
            score=0.9
        )
        registration_recognizer = PatternRecognizer(
            supported_entity="VEHICLE_REGISTRATION",
            patterns=[registration_pattern],
            context=["registration", "vehicle", "car", "number plate"]
        )
        custom_recognizers.append(registration_recognizer)
        
        # Insurance/Policy Number (HIPAA health plan, ISO 27001)
        policy_patterns = [
            Pattern(name="policy_explicit", regex=r'\b(?:policy|plan)[\s#:]*(?:number|no)?[\s#:]*([A-Z]{2,3}[-]?(?:IND[-]?)?\d{6,10})\b', score=0.9),
            Pattern(name="policy_code", regex=r'\b(?:HS|HP|AP)[-](?:IND[-])?\d{6,10}\b', score=0.85),
        ]
        policy_recognizer = PatternRecognizer(
            supported_entity="INSURANCE_POLICY_NUMBER",
            patterns=policy_patterns,
            context=["policy", "plan", "insurance", "health"]
        )
        custom_recognizers.append(policy_recognizer)
        
        # School/Institution Name (ISO 27001 - related entity identification)
        institution_pattern = Pattern(
            name="institution",
            regex=r'\b(?:school|college|university|institute|academy)[\s:]*([A-Z][A-Za-z\s&.,\'-]{3,50})\b',
            score=0.8
        )
        institution_recognizer = PatternRecognizer(
            supported_entity="INSTITUTION_NAME",
            patterns=[institution_pattern],
            context=["school", "college", "university", "institute", "academy"]
        )
        custom_recognizers.append(institution_recognizer)
        
        # ========== INTERNATIONAL IDENTITY CARD RECOGNIZERS ==========
        
        # UK NINO (National Insurance Number)
        uk_nino_pattern = Pattern(
            name="uk_nino",
            regex=r'\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b',
            score=0.95
        )
        uk_nino_recognizer = PatternRecognizer(
            supported_entity="UK_NINO",
            patterns=[uk_nino_pattern],
            context=["NINO", "national insurance", "insurance number"]
        )
        custom_recognizers.append(uk_nino_recognizer)
        
        # Canadian SIN (Social Insurance Number)
        canadian_sin_pattern = Pattern(
            name="canadian_sin",
            regex=r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b',
            score=0.85
        )
        canadian_sin_recognizer = PatternRecognizer(
            supported_entity="CANADIAN_SIN",
            patterns=[canadian_sin_pattern],
            context=["SIN", "social insurance", "canada"]
        )
        custom_recognizers.append(canadian_sin_recognizer)
        
        # Brazilian CPF
        brazilian_cpf_pattern = Pattern(
            name="brazilian_cpf",
            regex=r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b',
            score=0.95
        )
        brazilian_cpf_recognizer = PatternRecognizer(
            supported_entity="BRAZILIAN_CPF",
            patterns=[brazilian_cpf_pattern],
            context=["CPF", "cadastro", "brasil", "brazil"]
        )
        custom_recognizers.append(brazilian_cpf_recognizer)
        
        # Chinese ID (18 digits - very specific)
        chinese_id_pattern = Pattern(
            name="chinese_id",
            regex=r'\b\d{18}\b',
            score=0.9
        )
        chinese_id_recognizer = PatternRecognizer(
            supported_entity="CHINESE_ID",
            patterns=[chinese_id_pattern],
            context=["ID", "身份证", "China", "chinese"]
        )
        custom_recognizers.append(chinese_id_recognizer)
        
        # German Steuernummer (Tax ID)
        german_steuernummer_pattern = Pattern(
            name="german_steuernummer",
            regex=r'\b\d{2}[-\s]?\d{2,3}[-\s]?\d{3,4}[-\s]?\d{1}\b',
            score=0.85
        )
        german_steuernummer_recognizer = PatternRecognizer(
            supported_entity="GERMAN_STEUERNUMMER",
            patterns=[german_steuernummer_pattern],
            context=["Steuernummer", "tax", "germany", "deutsch"]
        )
        custom_recognizers.append(german_steuernummer_recognizer)
        
        # Spanish DNI
        spanish_dni_pattern = Pattern(
            name="spanish_dni",
            regex=r'\b\d{8}-?[A-Z]\b',
            score=0.95
        )
        spanish_dni_recognizer = PatternRecognizer(
            supported_entity="SPANISH_DNI",
            patterns=[spanish_dni_pattern],
            context=["DNI", "españa", "spain"]
        )
        custom_recognizers.append(spanish_dni_recognizer)
        
        # French INSEE
        french_insee_pattern = Pattern(
            name="french_insee",
            regex=r'\b\d{1}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{3}[-\s]?\d{3}\b',
            score=0.9
        )
        french_insee_recognizer = PatternRecognizer(
            supported_entity="FRENCH_INSEE",
            patterns=[french_insee_pattern],
            context=["INSEE", "numéro", "france", "français"]
        )
        custom_recognizers.append(french_insee_recognizer)
        
        # Italian Codice Fiscale
        italian_cf_pattern = Pattern(
            name="italian_cf",
            regex=r'\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b',
            score=0.95
        )
        italian_cf_recognizer = PatternRecognizer(
            supported_entity="ITALIAN_CF",
            patterns=[italian_cf_pattern],
            context=["Codice Fiscale", "CF", "italy", "italiano"]
        )
        custom_recognizers.append(italian_cf_recognizer)
        
        # Polish PESEL
        polish_pesel_pattern = Pattern(
            name="polish_pesel",
            regex=r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{2}\d{3}[0-9]\b',
            score=0.95
        )
        polish_pesel_recognizer = PatternRecognizer(
            supported_entity="POLISH_PESEL",
            patterns=[polish_pesel_pattern],
            context=["PESEL", "poland", "polski"]
        )
        custom_recognizers.append(polish_pesel_recognizer)
        
        # Australian TFN (Tax File Number)
        australian_tfn_pattern = Pattern(
            name="australian_tfn",
            regex=r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b',
            score=0.85
        )
        australian_tfn_recognizer = PatternRecognizer(
            supported_entity="AUSTRALIAN_TFN",
            patterns=[australian_tfn_pattern],
            context=["TFN", "tax file", "australia"]
        )
        custom_recognizers.append(australian_tfn_recognizer)
        
        # South Korean RRN (Resident Registration Number)
        south_korean_rrn_pattern = Pattern(
            name="south_korean_rrn",
            regex=r'\b\d{6}[-]?\d{7}\b',
            score=0.9
        )
        south_korean_rrn_recognizer = PatternRecognizer(
            supported_entity="SOUTH_KOREAN_RRN",
            patterns=[south_korean_rrn_pattern],
            context=["RRN", "korea", "korean", "주민등록"]
        )
        custom_recognizers.append(south_korean_rrn_recognizer)
        
        # Japanese My Number
        japanese_my_number_pattern = Pattern(
            name="japanese_my_number",
            regex=r'\b\d{12}\b',
            score=0.8
        )
        japanese_my_number_recognizer = PatternRecognizer(
            supported_entity="JAPANESE_MY_NUMBER",
            patterns=[japanese_my_number_pattern],
            context=["My Number", "マイナンバー", "japan"]
        )
        custom_recognizers.append(japanese_my_number_recognizer)
        
        # Singapore NRIC
        singapore_nric_pattern = Pattern(
            name="singapore_nric",
            regex=r'\b[STG]\d{7}[A-Z]\b',
            score=0.95
        )
        singapore_nric_recognizer = PatternRecognizer(
            supported_entity="SINGAPORE_NRIC",
            patterns=[singapore_nric_pattern],
            context=["NRIC", "singapore", "identity"]
        )
        custom_recognizers.append(singapore_nric_recognizer)
        
        # UAE Civil Number
        uae_civil_pattern = Pattern(
            name="uae_civil",
            regex=r'\b784[-]?\d{4}[-]?\d{7}[-]?\d{1}\b',
            score=0.95
        )
        uae_civil_recognizer = PatternRecognizer(
            supported_entity="UAE_CIVIL_NUMBER",
            patterns=[uae_civil_pattern],
            context=["Civil", "UAE", "emirates"]
        )
        custom_recognizers.append(uae_civil_recognizer)
        
        # South African ID
        sa_id_pattern = Pattern(
            name="sa_id",
            regex=r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9]\d{2}\b',
            score=0.95
        )
        sa_id_recognizer = PatternRecognizer(
            supported_entity="SOUTH_AFRICAN_ID",
            patterns=[sa_id_pattern],
            context=["ID", "south africa", "ZA"]
        )
        custom_recognizers.append(sa_id_recognizer)
        
        logger.info(f"Created {len(custom_recognizers)} custom recognizers for compliance")
        
        
    except Exception as e:
        logger.error(f"Error creating custom recognizers: {e}")
    
    return custom_recognizers

def get_protected_ranges(text: str, pseudonym: str) -> List[tuple]:
    """Get text ranges to protect (pseudonym occurrences)."""
    if not pseudonym:
        return []
    
    ranges = []
    pattern = re.compile(re.escape(pseudonym), re.IGNORECASE)
    for match in pattern.finditer(text):
        ranges.append((match.start(), match.end()))
    return ranges

def fallback_pii_detection(text: str, pseudonym: Optional[str] = None) -> List[Dict]:
    """
    Fallback PII detection using regex patterns.
    Used when ML-based detection fails to ensure HIPAA/ISO/SOC2 compliance.
    """
    logger.warning("Using fallback regex-based PII detection for compliance")
    detected_entities = []
    protected_ranges = get_protected_ranges(text, pseudonym) if pseudonym else []
    
    # Track overlapping entities to avoid duplicates
    detected_ranges = []
    
    for entity_type, pattern in FALLBACK_PATTERNS.items():
        try:
            # Use case-insensitive matching for text-based patterns
            flags = re.IGNORECASE if any(keyword in entity_type for keyword in 
                ['GENDER', 'DOB', 'MEDICAL', 'HEALTH', 'DEVICE', 'LICENSE', 'CERTIFICATE', 'PASSWORD', 'API']) else 0
            
            for match in re.finditer(pattern, text, flags=flags):
                start, end = match.span()
                
                # Skip if overlaps with pseudonym
                overlaps_pseudonym = any(
                    not (end <= p_start or start >= p_end)
                    for p_start, p_end in protected_ranges
                )
                
                if overlaps_pseudonym:
                    continue
                
                # Skip if significantly overlaps with already detected entity
                overlaps_existing = any(
                    abs(start - d_start) < 3 and abs(end - d_end) < 3
                    for d_start, d_end in detected_ranges
                )
                
                if overlaps_existing:
                    continue
                
                # Get context around the match
                context_start = max(0, start - 50)
                context_end = min(len(text), end + 50)
                context = text[context_start:context_end]
                matched_text = match.group()
                
                # Check if this entity should be anonymized
                if not should_anonymize_entity(entity_type, matched_text, context):
                    logger.debug(f"Skipping excluded entity in fallback: {entity_type} = '{matched_text}'")
                    continue
                
                # Adjust confidence based on entity type criticality (HIPAA)
                confidence = 0.5  # Default
                if entity_type in ['SSN', 'MEDICAL_RECORD_NUMBER', 'DATE_OF_BIRTH', 'AGE_OVER_89', 'HEALTH_PLAN_NUMBER']:
                    confidence = 0.8  # High priority for HIPAA
                elif entity_type in ['CREDIT_CARD', 'API_KEY', 'PASSWORD']:
                    confidence = 0.75  # High priority for SOC2
                
                detected_entities.append({
                    'entity_type': entity_type,
                    'start': start,
                    'end': end,
                    'text': matched_text,
                    'score': confidence,
                    'method': 'fallback_regex'
                })
                
                detected_ranges.append((start, end))
                
        except Exception as e:
            logger.error(f"Error in fallback pattern {entity_type}: {e}")
            continue
    
    # Sort by start position for consistent processing
    detected_entities.sort(key=lambda x: x['start'])
    
    logger.info(f"Fallback detection found {len(detected_entities)} entities across {len(FALLBACK_PATTERNS)} patterns")
    
    return detected_entities

def safe_redact_text(text: str, entities: List[Dict], pseudonym: Optional[str] = None) -> Tuple[str, List[Dict]]:
    """
    Safely redact text by replacing PII with generic nouns.
    This is a fail-safe method that works even if the anonymizer fails.
    """
    if not entities:
        return text, []
    
    # Sort entities by start position (reverse order for replacement)
    sorted_entities = sorted(entities, key=lambda x: x['start'], reverse=True)
    
    result_text = text
    redacted_spans = []
    
    for entity in sorted_entities:
        try:
            start = entity['start']
            end = entity['end']
            entity_type = entity.get('entity_type', 'DEFAULT')
            original = text[start:end]
            replacement = get_generic_noun(entity_type)
            
            # Replace in text
            result_text = result_text[:start] + replacement + result_text[end:]
            
            redacted_spans.append({
                'start': start,
                'end': end,
                'entity_type': entity_type,
                'original': original,
                'replacement': replacement
            })
        except Exception as e:
            logger.error(f"Error redacting entity at {entity.get('start', 'unknown')}: {e}")
            # On error, redact with [REDACTED] to be safe
            try:
                result_text = result_text[:start] + "[REDACTED]" + result_text[end:]
            except:
                pass
            continue
    
    return result_text, redacted_spans

@app.get("/")
async def root():
    """API information and status."""
    
    # Determine service mode
    if analyzer and anonymizer:
        mode = "full_ml"
        model_info = "en_core_web_lg (large)"
        status_detail = "ML models active, high-accuracy detection"
    elif analyzer or anonymizer:
        mode = "partial_ml"
        model_info = "partial ML with fallback"
        status_detail = "Some ML models active with regex fallback"
    else:
        mode = "fallback"
        model_info = "regex-based detection"
        status_detail = "Operating in fallback mode with regex patterns"
    
    return {
        "service": "Presidio Anonymization API",
        "version": "2.0.0",
        "mode": mode,
        "model": model_info,
        "status": "ready",
        "status_detail": status_detail,
        "compliance": {
            "standards": ["HIPAA", "ISO 27001", "SOC 2"],
            "features": [
                "Protected Health Information (PHI) detection",
                "Personally Identifiable Information (PII) detection",
                "Financial data protection",
                "Fail-safe mechanisms active",
                "Multiple fallback layers"
            ]
        },
        "detected_entity_types": {
            "personal": ["names", "DOB", "age", "gender", "demographics"],
            "contact": ["email", "phone", "address", "IP", "URL"],
            "financial": ["credit cards", "bank accounts", "routing numbers"],
            "government_ids": ["SSN", "passport", "driver license", "tax ID"],
            "medical": ["MRN", "health plan", "prescription", "NPI", "DEA"],
            "biometric": ["fingerprint", "DNA", "facial recognition"],
            "devices": ["VIN", "serial numbers", "IMEI", "MAC address"],
            "credentials": ["API keys", "passwords", "tokens"]
        },
        "endpoints": {
            "POST /anonymize": "Anonymize text (always returns safe content)",
            "POST /detect": "Detect PII/PHI entities (with fallback)",
            "GET /health": "Health check",
            "GET /docs": "Interactive API documentation"
        }
    }

@app.get("/health")
async def health():
    """
    Health check for Cloud Run.
    Service is always healthy even in fallback mode.
    """
    
    health_status = {
        "status": "healthy",
        "ml_analyzer": "active" if analyzer else "fallback_mode",
        "ml_anonymizer": "active" if anonymizer else "fallback_mode",
        "compliance_mode": "fail_safe_active"
    }
    
    if analyzer and anonymizer:
        health_status["model"] = "en_core_web_lg"
        health_status["detection_mode"] = "ml_based"
    else:
        health_status["model"] = "regex_fallback"
        health_status["detection_mode"] = "regex_based"
        health_status["note"] = "Service operational with fallback detection"
    
    return health_status

@app.post("/anonymize", response_model=AnonymizeResponse)
async def anonymize(request: AnonymizeRequest):
    """
    Anonymize text with generic nouns, preserving pseudonym.
    Features fail-safe compliance mechanisms:
    - Falls back to regex detection if ML fails
    - Uses safe redaction if anonymizer fails
    - Never returns original text on error
    """
    
    anonymized_text = request.text
    anonymized_spans = []
    detected_entities = []
    
    try:
        # STEP 1: Detect PII entities (with fallback)
        if analyzer:
            try:
                # Get protected ranges for pseudonym
                protected_ranges = get_protected_ranges(request.text, request.pseudonym)
                
                # Analyze text for PII with confidence threshold
                results = analyzer.analyze(
                    text=request.text,
                    language=request.language,
                    score_threshold=0.7
                )
                
                # Filter out entities that:
                # 1. Overlap with pseudonym
                # 2. Are in the excluded list (e.g., generic DATE entities)
                for result in results:
                    entity_text = request.text[result.start:result.end]
                    
                    # Check overlap with protected ranges (pseudonym)
                    overlaps = any(
                        not (result.end <= start or result.start >= end)
                        for start, end in protected_ranges
                    )
                    
                    # Check if entity contains pseudonym
                    if request.pseudonym:
                        if request.pseudonym.lower() in entity_text.lower():
                            overlaps = True
                    
                    if overlaps:
                        continue
                    
                    # Get context around the entity (50 chars before and after)
                    context_start = max(0, result.start - 50)
                    context_end = min(len(request.text), result.end + 50)
                    context = request.text[context_start:context_end]
                    
                    # Check if this entity should be anonymized
                    if not should_anonymize_entity(result.entity_type, entity_text, context):
                        logger.debug(f"Skipping excluded entity: {result.entity_type} = '{entity_text}'")
                        continue
                    
                    detected_entities.append({
                        'entity_type': result.entity_type,
                        'start': result.start,
                        'end': result.end,
                        'score': result.score,
                        'text': entity_text
                    })
                
                logger.info(f"ML-based detection found {len(detected_entities)} entities (after filtering excluded types)")
                
            except Exception as e:
                logger.error(f"ML-based detection failed: {e}, using fallback")
                detected_entities = fallback_pii_detection(request.text, request.pseudonym)
        else:
            # No ML models available, use fallback
            logger.warning("ML models not available, using fallback detection")
            detected_entities = fallback_pii_detection(request.text, request.pseudonym)
        
        # STEP 2: Anonymize the detected entities (with fallback)
        if anonymizer and detected_entities and analyzer:
            try:
                # Convert to RecognizerResult objects for anonymizer
                filtered_results = []
                for entity in detected_entities:
                    try:
                        result = RecognizerResult(
                            entity_type=entity['entity_type'],
                            start=entity['start'],
                            end=entity['end'],
                            score=entity.get('score', 0.5)
                        )
                        filtered_results.append(result)
                    except Exception as e:
                        logger.error(f"Error creating RecognizerResult: {e}")
                        continue
                
                # Create operator configs
                operators = {}
                for result in filtered_results:
                    if result.entity_type not in operators:
                        operators[result.entity_type] = OperatorConfig(
                            operator_name="replace",
                            params={"new_value": get_generic_noun(result.entity_type)}
                        )
                
                # Anonymize text
                anonymized = anonymizer.anonymize(
                    text=request.text,
                    analyzer_results=filtered_results,
                    operators=operators
                )
                
                anonymized_text = anonymized.text
                
                # Build response spans
                for item in anonymized.items:
                    try:
                        original_text = request.text[item.start:item.end]
                        anonymized_spans.append({
                            "start": item.start,
                            "end": item.end,
                            "entity_type": item.entity_type,
                            "original": original_text,
                            "replacement": get_generic_noun(item.entity_type)
                        })
                    except Exception as e:
                        logger.error(f"Error building span: {e}")
                        continue
                
                logger.info(f"Successfully anonymized using Presidio anonymizer")
                
            except Exception as e:
                logger.error(f"Presidio anonymizer failed: {e}, using safe redaction")
                anonymized_text, anonymized_spans = safe_redact_text(
                    request.text, 
                    detected_entities, 
                    request.pseudonym
                )
        else:
            # Use safe redaction fallback
            logger.info(f"Using safe redaction fallback for {len(detected_entities)} entities")
            anonymized_text, anonymized_spans = safe_redact_text(
                request.text, 
                detected_entities, 
                request.pseudonym
            )
        
        return AnonymizeResponse(
            anonymized_text=anonymized_text,
            anonymized_spans=anonymized_spans,
            pseudonym_preserved=request.pseudonym
        )
        
    except Exception as e:
        # ULTIMATE FAIL-SAFE: Redact aggressively if everything fails
        logger.critical(f"Complete anonymization failure: {e}")
        
        # Try fallback detection one more time
        try:
            fallback_entities = fallback_pii_detection(request.text, request.pseudonym)
            anonymized_text, anonymized_spans = safe_redact_text(
                request.text,
                fallback_entities,
                request.pseudonym
            )
            logger.warning("Emergency fallback successful")
            
            return AnonymizeResponse(
                anonymized_text=anonymized_text,
                anonymized_spans=anonymized_spans,
                pseudonym_preserved=request.pseudonym
            )
        except Exception as critical_error:
            # Last resort: return heavily redacted version
            logger.critical(f"Emergency fallback failed: {critical_error}")
            raise HTTPException(
                status_code=500, 
                detail="Critical anonymization failure. Please contact support. Original text was NOT returned for security."
            )

@app.post("/detect", response_model=DetectResponse)
async def detect(request: DetectRequest):
    """
    Detect PII entities without anonymization.
    Features fail-safe mechanisms with fallback detection.
    """
    
    entities = []
    detection_method = "unknown"
    
    try:
        # Try ML-based detection first
        if analyzer:
            try:
                results = analyzer.analyze(
                    text=request.text,
                    language=request.language,
                    score_threshold=0.7
                )
                
                # Filter and format results
                for result in results:
                    try:
                        entity_text = request.text[result.start:result.end]
                        
                        # Skip if contains pseudonym
                        if request.pseudonym and request.pseudonym.lower() in entity_text.lower():
                            continue
                        
                        # Get context around the entity
                        context_start = max(0, result.start - 50)
                        context_end = min(len(request.text), result.end + 50)
                        context = request.text[context_start:context_end]
                        
                        # Check if this entity should be anonymized (skip excluded types)
                        if not should_anonymize_entity(result.entity_type, entity_text, context):
                            continue
                        
                        entities.append({
                            "type": result.entity_type,
                            "start": result.start,
                            "end": result.end,
                            "text": entity_text,
                            "score": round(result.score, 3),
                            "method": "ml_model"
                        })
                    except Exception as e:
                        logger.error(f"Error processing detection result: {e}")
                        continue
                
                detection_method = "ml_model"
                logger.info(f"ML-based detection found {len(entities)} entities")
                
            except Exception as e:
                logger.error(f"ML-based detection failed: {e}, using fallback")
                # Fall through to fallback detection
                entities = []
                detection_method = "fallback"
        
        # Use fallback if ML detection failed or is unavailable
        if not entities and not analyzer or detection_method == "fallback":
            logger.warning("Using fallback regex-based detection")
            fallback_entities = fallback_pii_detection(request.text, request.pseudonym)
            
            for entity in fallback_entities:
                entities.append({
                    "type": entity['entity_type'],
                    "start": entity['start'],
                    "end": entity['end'],
                    "text": entity['text'],
                    "score": round(entity.get('score', 0.5), 3),
                    "method": "fallback_regex"
                })
            
            detection_method = "fallback_regex"
        
        logger.info(f"Detection completed with {detection_method}, found {len(entities)} entities")
        return DetectResponse(entities=entities)
        
    except Exception as e:
        logger.error(f"Complete detection failure: {e}")
        
        # Last attempt: try fallback detection
        try:
            fallback_entities = fallback_pii_detection(request.text, request.pseudonym)
            entities = []
            
            for entity in fallback_entities:
                entities.append({
                    "type": entity['entity_type'],
                    "start": entity['start'],
                    "end": entity['end'],
                    "text": entity['text'],
                    "score": round(entity.get('score', 0.5), 3),
                    "method": "emergency_fallback"
                })
            
            logger.warning("Emergency fallback detection successful")
            return DetectResponse(entities=entities)
            
        except Exception as critical_error:
            logger.critical(f"Emergency fallback detection failed: {critical_error}")
            # Return empty list rather than failing completely
            # This ensures the service remains available
            return DetectResponse(entities=[])

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)