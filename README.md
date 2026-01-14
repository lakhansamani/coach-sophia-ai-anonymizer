# Presidio Service for Generic Noun Anonymization

This service uses Microsoft Presidio to anonymize PII by replacing it with generic nouns (friend, colleague, person, organization, place) while preserving user-chosen pseudonyms.

## Setup

### Option 1: Local Development

#### 1. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy English model (required for Presidio)
python -m spacy download en_core_web_sm
```

#### 2. Run the Service

```bash
python app.py
```

Service will run on `http://localhost:5000`

### Option 2: Docker (Recommended)

#### Build and Run with Docker

```bash
# Build the image
docker build -t presidio-service .

# Run the container
docker run -d -p 5000:5000 --name presidio-service presidio-service
```

#### Using Docker Compose

```bash
# Build and start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

## API Endpoints

### POST /anonymize

Anonymize text with generic nouns.

**Request:**
```json
{
  "text": "I want to discuss my friend Lakhan Samani",
  "pseudonym": "sanfran2025",
  "language": "en"
}
```

**Response:**
```json
{
  "anonymized_text": "I want to discuss my friend",
  "anonymized_spans": [
    {
      "start": 28,
      "end": 42,
      "original": "Lakhan Samani",
      "replacement": "friend",
      "entity_type": "PERSON"
    }
  ],
  "pseudonym_preserved": "sanfran2025"
}
```

### POST /detect

Detect PII entities without anonymization.

**Request:**
```json
{
  "text": "I want to discuss my friend Lakhan Samani",
  "pseudonym": "sanfran2025",
  "language": "en"
}
```

**Response:**
```json
{
  "entities": [
    {
      "type": "PERSON",
      "start": 28,
      "end": 42,
      "text": "Lakhan Samani",
      "score": 0.95
    }
  ]
}
```

### GET /health

Health check endpoint.

## Docker Deployment

The Dockerfile includes:
- Python 3.11 slim base image
- All required dependencies
- spaCy English model
- Non-root user for security
- Health checks
- Optimized layer caching

### Environment Variables

- `PORT` - Server port (default: 5000)
- `FLASK_ENV` - Flask environment (development/production)

### Building for Production

```bash
# Build optimized image
docker build -t presidio-service:latest .

# Run with custom port
docker run -d -p 8080:8080 -e PORT=8080 presidio-service:latest
```

## Generic Noun Mappings

The service replaces PII with generic nouns:

- **PERSON** → friend, colleague, person, individual, someone
- **EMAIL** → email address
- **PHONE_NUMBER** → phone number
- **LOCATION** → place, location, area
- **ORGANIZATION** → organization, company, institution
- **DATE_TIME** → date, time
- **ADDRESS** → address
- **CREDIT_CARD** → payment method
- **SSN** → identification number
- And more...

## Pseudonym Preservation

The service automatically preserves user-chosen pseudonyms (e.g., "sanfran2025") and excludes them from anonymization.

## Integration with Supabase Edge Functions

The service is designed to be called from Supabase Edge Functions running in Docker. Use `http://host.docker.internal:5000` to access the service from within Docker containers.
