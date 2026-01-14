"""
Presidio REST API with Large SpaCy Model
Optimized for Google Cloud Run deployment
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import os
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    
    try:
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()
        
        # Initialize with additional recognizers if needed
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"]
        )
        anonymizer = AnonymizerEngine()
        
        logger.info("✅ Presidio engines initialized with large model")
        
    except Exception as e:
        logger.error(f"Failed to initialize Presidio: {e}")
        raise

# Enhanced generic noun mappings
GENERIC_NOUNS = {
    'PERSON': 'person',
    'EMAIL_ADDRESS': 'email',
    'PHONE_NUMBER': 'phone',
    'LOCATION': 'location',
    'GPE': 'location',  # Geopolitical entity
    'LOC': 'location',  # Location
    'ORGANIZATION': 'organization',
    'ORG': 'organization',
    'DATE_TIME': 'date',
    'DATE': 'date',
    'TIME': 'time',
    'CREDIT_CARD': 'payment',
    'IP_ADDRESS': 'address',
    'URL': 'website',
    'US_SSN': 'identifier',
    'US_DRIVER_LICENSE': 'identifier',
    'US_PASSPORT': 'identifier',
    'IBAN_CODE': 'account',
    'CRYPTO': 'wallet',
    'MEDICAL_LICENSE': 'license',
    'DEFAULT': 'information'
}

def get_generic_noun(entity_type: str) -> str:
    """Get generic noun for entity type."""
    return GENERIC_NOUNS.get(entity_type.upper(), GENERIC_NOUNS['DEFAULT'])

def get_protected_ranges(text: str, pseudonym: str) -> List[tuple]:
    """Get text ranges to protect (pseudonym occurrences)."""
    if not pseudonym:
        return []
    
    ranges = []
    pattern = re.compile(re.escape(pseudonym), re.IGNORECASE)
    for match in pattern.finditer(text):
        ranges.append((match.start(), match.end()))
    return ranges

@app.get("/")
async def root():
    """API information and status."""
    return {
        "service": "Presidio Anonymization API",
        "version": "2.0.0",
        "model": "en_core_web_lg (large)",
        "status": "ready" if analyzer else "initializing",
        "endpoints": {
            "POST /anonymize": "Anonymize text with high accuracy",
            "POST /detect": "Detect PII entities",
            "GET /health": "Health check",
            "GET /docs": "Interactive API documentation"
        }
    }

@app.get("/health")
async def health():
    """Health check for Cloud Run."""
    if not analyzer or not anonymizer:
        raise HTTPException(status_code=503, detail="Service initializing")
    return {"status": "healthy", "model": "en_core_web_lg"}

@app.post("/anonymize", response_model=AnonymizeResponse)
async def anonymize(request: AnonymizeRequest):
    """Anonymize text with generic nouns, preserving pseudonym."""
    
    if not analyzer or not anonymizer:
        raise HTTPException(status_code=503, detail="Service still initializing")
    
    try:
        # Get protected ranges for pseudonym
        protected_ranges = get_protected_ranges(request.text, request.pseudonym)
        
        # Analyze text for PII with confidence threshold
        results = analyzer.analyze(
            text=request.text,
            language=request.language,
            score_threshold=0.7  # Adjust confidence threshold
        )
        
        # Filter out entities that overlap with pseudonym
        filtered_results = []
        for result in results:
            # Check overlap with protected ranges
            overlaps = any(
                not (result.end <= start or result.start >= end)
                for start, end in protected_ranges
            )
            
            # Check if entity contains pseudonym
            if request.pseudonym:
                entity_text = request.text[result.start:result.end]
                if request.pseudonym.lower() in entity_text.lower():
                    overlaps = True
            
            if not overlaps:
                filtered_results.append(result)
        
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
        
        # Build response
        anonymized_spans = []
        for item in anonymized.items:
            original_text = request.text[item.start:item.end]
            anonymized_spans.append({
                "start": item.start,
                "end": item.end,
                "entity_type": item.entity_type,
                "original": original_text,
                "replacement": get_generic_noun(item.entity_type)
            })
        
        return AnonymizeResponse(
            anonymized_text=anonymized.text,
            anonymized_spans=anonymized_spans,
            pseudonym_preserved=request.pseudonym
        )
        
    except Exception as e:
        logger.error(f"Anonymization error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/detect", response_model=DetectResponse)
async def detect(request: DetectRequest):
    """Detect PII entities without anonymization."""
    
    if not analyzer:
        raise HTTPException(status_code=503, detail="Service still initializing")
    
    try:
        # Analyze text with large model
        results = analyzer.analyze(
            text=request.text,
            language=request.language,
            score_threshold=0.7
        )
        
        # Filter and format results
        entities = []
        for result in results:
            entity_text = request.text[result.start:result.end]
            
            # Skip if contains pseudonym
            if request.pseudonym and request.pseudonym.lower() in entity_text.lower():
                continue
                
            entities.append({
                "type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "text": entity_text,
                "score": round(result.score, 3)
            })
        
        return DetectResponse(entities=entities)
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)