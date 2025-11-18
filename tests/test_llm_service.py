import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.services.llm_service import LLMService
from app.models import ThreatData, AIAnalysis


class TestLLMService:
    """Tests for LLM service"""

    def test_init_with_api_key(self):
        service = LLMService(api_key="test_key")
        assert service.api_key == "test_key"
        assert service.client is not None

    def test_init_without_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            service = LLMService()
            assert service.client is None

    def test_build_prompt(self):
        service = LLMService(api_key="test_key")
        threat_data = ThreatData(
            ip_address="8.8.8.8",
            hostname="dns.google",
            isp="Google LLC",
            country="United States",
            abuse_score=0,
            recent_reports=0,
            vpn_detected=False,
            proxy_detected=False,
            fraud_score=5,
            is_tor=False
        )

        prompt = service._build_prompt("8.8.8.8", threat_data)

        assert "8.8.8.8" in prompt
        assert "dns.google" in prompt
        assert "Google LLC" in prompt
        assert "risk_level" in prompt
        assert "recommendations" in prompt

    @pytest.mark.asyncio
    async def test_llm_analysis_success(self):
        service = LLMService(api_key="test_key")

        # Mock Groq API response
        mock_response = Mock()
        mock_response.choices = [
            Mock(message=Mock(content='{"risk_level": "Low", "risk_analysis": "This IP is safe", "recommendations": ["Monitor", "No action needed"]}'))
        ]

        with patch.object(service.client.chat.completions, "create", return_value=mock_response):
            threat_data = ThreatData(
                ip_address="8.8.8.8",
                abuse_score=0,
                recent_reports=0,
                fraud_score=5,
                vpn_detected=False,
                is_tor=False
            )

            result = await service._llm_analysis("8.8.8.8", threat_data)

            assert result is not None
            assert result.risk_level == "Low"
            assert result.risk_analysis == "This IP is safe"
            assert len(result.recommendations) == 2

    @pytest.mark.asyncio
    async def test_llm_analysis_failure_returns_none(self):
        service = LLMService(api_key="test_key")

        with patch.object(service.client.chat.completions, "create", side_effect=Exception("API Error")):
            threat_data = ThreatData(
                ip_address="8.8.8.8",
                abuse_score=0,
                recent_reports=0
            )

            result = await service._llm_analysis("8.8.8.8", threat_data)
            assert result is None

    def test_rule_based_analysis_low_risk(self):
        service = LLMService()

        threat_data = ThreatData(
            ip_address="8.8.8.8",
            abuse_score=0,
            recent_reports=0,
            fraud_score=5,
            vpn_detected=False,
            proxy_detected=False,
            is_tor=False
        )

        result = service._rule_based_analysis(threat_data)

        assert result.risk_level == "Low"
        assert "No significant threat" in result.risk_analysis or "legitimate" in result.risk_analysis
        assert len(result.recommendations) > 0

    def test_rule_based_analysis_medium_risk(self):
        service = LLMService()

        threat_data = ThreatData(
            ip_address="1.2.3.4",
            abuse_score=35,
            recent_reports=5,
            fraud_score=50,
            vpn_detected=True,
            proxy_detected=False,
            is_tor=False
        )

        result = service._rule_based_analysis(threat_data)

        assert result.risk_level == "Medium"
        assert "abuse score" in result.risk_analysis.lower()
        assert len(result.recommendations) > 0

    def test_rule_based_analysis_high_risk(self):
        service = LLMService()

        threat_data = ThreatData(
            ip_address="1.2.3.4",
            abuse_score=85,
            recent_reports=25,
            fraud_score=90,
            vpn_detected=False,
            proxy_detected=False,
            is_tor=True
        )

        result = service._rule_based_analysis(threat_data)

        assert result.risk_level == "High"
        assert "Tor" in result.risk_analysis or "high" in result.risk_analysis.lower()
        assert len(result.recommendations) > 0
        assert any("block" in rec.lower() for rec in result.recommendations)

    def test_generate_recommendations_high_risk(self):
        service = LLMService()

        threat_data = ThreatData(
            ip_address="1.2.3.4",
            is_tor=True
        )

        recommendations = service._generate_recommendations("High", threat_data)

        assert len(recommendations) > 0
        assert any("block" in rec.lower() for rec in recommendations)

    def test_generate_recommendations_medium_risk(self):
        service = LLMService()

        threat_data = ThreatData(
            ip_address="1.2.3.4",
            vpn_detected=True
        )

        recommendations = service._generate_recommendations("Medium", threat_data)

        assert len(recommendations) > 0
        assert any("monitor" in rec.lower() for rec in recommendations)

    def test_generate_recommendations_low_risk(self):
        service = LLMService()

        threat_data = ThreatData(
            ip_address="8.8.8.8"
        )

        recommendations = service._generate_recommendations("Low", threat_data)

        assert len(recommendations) > 0
        assert any("no immediate action" in rec.lower() for rec in recommendations)

    @pytest.mark.asyncio
    async def test_analyze_threats_with_aggregation(self):
        service = LLMService(api_key="test_key")

        raw_threat_data = {
            "abuseipdb": {"abuse_score": 10, "recent_reports": 2},
            "ipqualityscore": {"fraud_score": 20, "vpn": False},
            "ipapi": {"country": "US", "isp": "Google LLC"}
        }

        # Mock LLM response
        mock_response = Mock()
        mock_response.choices = [
            Mock(message=Mock(content='{"risk_level": "Low", "risk_analysis": "Safe IP", "recommendations": ["Monitor"]}'))
        ]

        with patch.object(service.client.chat.completions, "create", return_value=mock_response):
            result = await service.analyze_threats("8.8.8.8", raw_threat_data)

            assert isinstance(result, AIAnalysis)
            assert result.risk_level == "Low"

    @pytest.mark.asyncio
    async def test_analyze_threats_fallback_to_rules(self):
        service = LLMService()  # No API key, will use rule-based

        raw_threat_data = {
            "abuseipdb": {"abuse_score": 75, "recent_reports": 15},
            "ipqualityscore": {"fraud_score": 80, "vpn": False, "tor": True},
            "ipapi": {"country": "Unknown"}
        }

        result = await service.analyze_threats("1.2.3.4", raw_threat_data)

        assert isinstance(result, AIAnalysis)
        assert result.risk_level in ["Low", "Medium", "High"]
        assert len(result.recommendations) > 0