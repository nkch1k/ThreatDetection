import pytest
from unittest.mock import AsyncMock, patch
from app.services.threat_apis import (
    AbuseIPDBClient,
    IPQualityScoreClient,
    IPAPIClient,
    ThreatAPIClient
)


class TestAbuseIPDBClient:
    """Tests for AbuseIPDB API client"""

    @pytest.mark.asyncio
    async def test_check_ip_success(self):
        client = AbuseIPDBClient(api_key="test_key")

        mock_response = {
            "data": {
                "abuseConfidenceScore": 25,
                "totalReports": 5,
                "isWhitelisted": False,
                "countryCode": "US",
                "usageType": "Data Center",
                "isp": "Google LLC",
                "domain": "google.com",
                "hostnames": ["dns.google"]
            }
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response_obj = AsyncMock()
            mock_response_obj.json.return_value = mock_response
            mock_response_obj.raise_for_status = AsyncMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response_obj
            )

            result = await client.check_ip("8.8.8.8")

            assert result["abuse_score"] == 25
            assert result["recent_reports"] == 5
            assert result["is_whitelisted"] is False
            assert result["country_code"] == "US"
            assert result["isp"] == "Google LLC"

    @pytest.mark.asyncio
    async def test_check_ip_no_api_key(self):
        client = AbuseIPDBClient(api_key=None)
        result = await client.check_ip("8.8.8.8")

        assert "error" in result
        assert "not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_check_ip_timeout(self):
        client = AbuseIPDBClient(api_key="test_key")

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("Timeout")
            )

            result = await client.check_ip("8.8.8.8")
            assert "error" in result


class TestIPQualityScoreClient:
    """Tests for IPQualityScore API client"""

    @pytest.mark.asyncio
    async def test_check_ip_success(self):
        client = IPQualityScoreClient(api_key="test_key")

        mock_response = {
            "fraud_score": 75,
            "vpn": True,
            "tor": False,
            "proxy": True,
            "bot_status": False,
            "recent_abuse": True,
            "country_code": "RU",
            "region": "Moscow",
            "city": "Moscow",
            "ISP": "Unknown ISP",
            "organization": "VPN Provider"
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response_obj = AsyncMock()
            mock_response_obj.json.return_value = mock_response
            mock_response_obj.raise_for_status = AsyncMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response_obj
            )

            result = await client.check_ip("1.2.3.4")

            assert result["fraud_score"] == 75
            assert result["vpn"] is True
            assert result["proxy"] is True
            assert result["tor"] is False
            assert result["recent_abuse"] is True

    @pytest.mark.asyncio
    async def test_check_ip_no_api_key(self):
        client = IPQualityScoreClient(api_key=None)
        result = await client.check_ip("1.2.3.4")

        assert "error" in result
        assert "not configured" in result["error"]


class TestIPAPIClient:
    """Tests for IPAPI client"""

    @pytest.mark.asyncio
    async def test_check_ip_success(self):
        client = IPAPIClient()

        mock_response = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "region": "CA",
            "city": "Mountain View",
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as": "AS15169 Google LLC"
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response_obj = AsyncMock()
            mock_response_obj.json.return_value = mock_response
            mock_response_obj.raise_for_status = AsyncMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response_obj
            )

            result = await client.check_ip("8.8.8.8")

            assert result["country"] == "United States"
            assert result["country_code"] == "US"
            assert result["city"] == "Mountain View"
            assert result["isp"] == "Google LLC"

    @pytest.mark.asyncio
    async def test_check_ip_failed_lookup(self):
        client = IPAPIClient()

        mock_response = {
            "status": "fail",
            "message": "invalid query"
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response_obj = AsyncMock()
            mock_response_obj.json.return_value = mock_response
            mock_response_obj.raise_for_status = AsyncMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response_obj
            )

            result = await client.check_ip("invalid")

            assert "error" in result
            assert "failed" in result["error"]


class TestThreatAPIClient:
    """Tests for unified threat API client"""

    @pytest.mark.asyncio
    async def test_check_ip_aggregates_all_sources(self):
        client = ThreatAPIClient()

        with patch.object(client.abuseipdb, "check_ip", new=AsyncMock(return_value={"abuse_score": 0})), \
             patch.object(client.ipqualityscore, "check_ip", new=AsyncMock(return_value={"fraud_score": 10})), \
             patch.object(client.ipapi, "check_ip", new=AsyncMock(return_value={"country": "US"})):

            result = await client.check_ip("8.8.8.8")

            assert "abuseipdb" in result
            assert "ipqualityscore" in result
            assert "ipapi" in result
            assert result["abuseipdb"]["abuse_score"] == 0
            assert result["ipqualityscore"]["fraud_score"] == 10
            assert result["ipapi"]["country"] == "US"

    @pytest.mark.asyncio
    async def test_check_ip_handles_partial_failures(self):
        client = ThreatAPIClient()

        with patch.object(client.abuseipdb, "check_ip", new=AsyncMock(return_value={"error": "API error"})), \
             patch.object(client.ipqualityscore, "check_ip", new=AsyncMock(return_value={"fraud_score": 10})), \
             patch.object(client.ipapi, "check_ip", new=AsyncMock(return_value={"country": "US"})):

            result = await client.check_ip("8.8.8.8")

            assert "abuseipdb" in result
            assert "error" in result["abuseipdb"]
            assert result["ipqualityscore"]["fraud_score"] == 10
            assert result["ipapi"]["country"] == "US"
