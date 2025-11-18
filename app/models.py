from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from app.utils.validators import validate_ip_address


class ThreatCheckRequest(BaseModel):
    """Request model for IP threat check"""
    ip_address: str = Field(..., description="IP address to check for threats")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        is_valid, error = validate_ip_address(v)
        if not is_valid:
            raise ValueError(error)
        return v.strip()


class ThreatData(BaseModel):
    """Aggregated threat intelligence data from multiple sources"""
    ip_address: str
    hostname: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    abuse_score: Optional[int] = None
    recent_reports: Optional[int] = None
    vpn_detected: Optional[bool] = None
    proxy_detected: Optional[bool] = None
    fraud_score: Optional[int] = None
    is_tor: Optional[bool] = None


class AIAnalysis(BaseModel):
    """AI-generated risk analysis"""
    risk_level: str = Field(..., description="Risk level: Low, Medium, or High")
    risk_analysis: str = Field(..., description="Natural language risk assessment")
    recommendations: List[str] = Field(..., description="List of security recommendations")


class ThreatCheckResponse(BaseModel):
    """Response model for IP threat check"""
    threat_data: ThreatData
    ai_analysis: AIAnalysis
    cached: bool = Field(default=False, description="Whether data was retrieved from cache")