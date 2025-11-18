from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
from app.services.threat_apis import ThreatAPIClient
from app.services.llm_service import LLMService
from app.services.aggregator import ThreatDataAggregator
from app.services.cache import ThreatCache
from app.utils.validators import validate_ip_address

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="IP Threat Intelligence API",
    description="AI-powered IP threat detection and analysis system",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
threat_client = ThreatAPIClient()
llm_service = LLMService()
cache = ThreatCache(ttl=300)  # 5 minutes TTL


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "IP Threat Intelligence API",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "/api/analyze-ip?ip={ip_address}",
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "services": {
            "cache": cache.size(),
            "llm": "configured" if llm_service.client else "fallback mode"
        }
    }


@app.get("/api/analyze-ip", tags=["Threat Detection"])
async def analyze_ip(
    ip: str = Query(..., description="IP address to analyze for threats")
):
    """
    Analyze IP address for threats using multiple intelligence sources and AI.

    This endpoint:
    1. Validates the IP address format and rejects private IPs
    2. Checks cache for recent results (5 min TTL)
    3. Queries multiple threat intelligence APIs (AbuseIPDB, IPQualityScore, IPAPI)
    4. Uses AI (Groq LLM) to analyze and synthesize threat data
    5. Returns comprehensive risk assessment with recommendations

    Args:
        ip: Public IPv4 address to analyze

    Returns:
        JSON with threat data, AI analysis, and risk assessment

    Raises:
        HTTPException: For invalid IPs, API failures, or server errors
    """
    try:
        # Step 1: Validate IP address
        is_valid, error_message = validate_ip_address(ip)
        if not is_valid:
            logger.warning(f"Invalid IP validation: {error_message}")
            raise HTTPException(status_code=400, detail=error_message)

        # Step 2: Check cache
        cached_result = cache.get(ip)
        if cached_result:
            logger.info(f"Cache hit for IP: {ip}")
            cached_result["cached"] = True
            return JSONResponse(content=cached_result)

        logger.info(f"Cache miss for IP: {ip}, fetching from APIs")

        # Step 3: Fetch threat data from multiple sources
        try:
            raw_threat_data = await threat_client.check_ip(ip)
        except Exception as e:
            logger.error(f"Error fetching threat data for {ip}: {e}")
            raise HTTPException(
                status_code=502,
                detail="Failed to fetch threat intelligence data from external APIs"
            )

        # Step 4: Check if all sources failed
        if ThreatDataAggregator.has_errors(raw_threat_data):
            logger.error(f"All threat intelligence sources failed for {ip}")
            raise HTTPException(
                status_code=503,
                detail="All threat intelligence sources are currently unavailable"
            )

        # Step 5: Aggregate threat data
        threat_data = ThreatDataAggregator.aggregate({
            **raw_threat_data,
            "ip_address": ip
        })

        # Step 6: Analyze with AI/LLM
        try:
            ai_analysis = await llm_service.analyze_threats(ip, raw_threat_data)
        except Exception as e:
            logger.error(f"Error during AI analysis for {ip}: {e}")
            raise HTTPException(
                status_code=500,
                detail="Failed to perform AI analysis on threat data"
            )

        # Step 7: Build response
        response_data = {
            "threat_data": threat_data.model_dump(),
            "ai_analysis": ai_analysis.model_dump(),
            "cached": False,
            "sources_used": ThreatDataAggregator.get_working_sources(raw_threat_data)
        }

        # Step 8: Cache the result
        cache.set(ip, response_data)
        logger.info(f"Successfully analyzed IP: {ip}, risk level: {ai_analysis.risk_level}")

        return JSONResponse(content=response_data)

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Catch-all for unexpected errors
        logger.error(f"Unexpected error analyzing IP {ip}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/cache/stats", tags=["Cache"])
async def cache_stats():
    """Get cache statistics"""
    return {
        "size": cache.size(),
        "ttl_seconds": cache._ttl
    }


@app.post("/cache/clear", tags=["Cache"])
async def clear_cache():
    """Clear all cached entries"""
    cache.clear()
    return {"message": "Cache cleared successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

