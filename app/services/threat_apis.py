import httpx
import os
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()


class AbuseIPDBClient:
    """Client for AbuseIPDB API - provides abuse reports and reputation scores"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address against AbuseIPDB.

        Args:
            ip_address: IP address to check

        Returns:
            Dict containing abuse score, reports count, and other metadata
        """
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self.headers,
                    params={
                        "ipAddress": ip_address,
                        "maxAgeInDays": "90",
                        "verbose": ""
                    }
                )
                response.raise_for_status()
                data = response.json()

                # Extract relevant fields
                ip_data = data.get("data", {})
                return {
                    "abuse_score": ip_data.get("abuseConfidenceScore", 0),
                    "recent_reports": ip_data.get("totalReports", 0),
                    "is_whitelisted": ip_data.get("isWhitelisted", False),
                    "country_code": ip_data.get("countryCode"),
                    "usage_type": ip_data.get("usageType"),
                    "isp": ip_data.get("isp"),
                    "domain": ip_data.get("domain"),
                    "hostnames": ip_data.get("hostnames", []),
                }

        except httpx.TimeoutException:
            return {"error": "AbuseIPDB request timeout"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"error": "AbuseIPDB rate limit exceeded"}
            return {"error": f"AbuseIPDB HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"AbuseIPDB error: {str(e)}"}


class IPQualityScoreClient:
    """Client for IPQualityScore API - provides VPN/proxy detection and fraud scores"""

    BASE_URL = "https://ipqualityscore.com/api/json/ip"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("IPQUALITYSCORE_API_KEY")

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address against IPQualityScore.

        Args:
            ip_address: IP address to check

        Returns:
            Dict containing fraud score, VPN/proxy detection, and other metadata
        """
        if not self.api_key:
            return {"error": "IPQualityScore API key not configured"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/{self.api_key}/{ip_address}",
                    params={
                        "strictness": 0,
                        "allow_public_access_points": "true"
                    }
                )
                response.raise_for_status()
                data = response.json()

                return {
                    "fraud_score": data.get("fraud_score", 0),
                    "vpn": data.get("vpn", False),
                    "tor": data.get("tor", False),
                    "proxy": data.get("proxy", False),
                    "bot_status": data.get("bot_status", False),
                    "recent_abuse": data.get("recent_abuse", False),
                    "country_code": data.get("country_code"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "isp": data.get("ISP"),
                    "organization": data.get("organization"),
                }

        except httpx.TimeoutException:
            return {"error": "IPQualityScore request timeout"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"error": "IPQualityScore rate limit exceeded"}
            return {"error": f"IPQualityScore HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"IPQualityScore error: {str(e)}"}


class IPAPIClient:
    """Client for IPAPI - provides geolocation data (no API key required)"""

    BASE_URL = "http://ip-api.com/json"

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get geolocation data for IP address.

        Args:
            ip_address: IP address to check

        Returns:
            Dict containing geolocation data
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/{ip_address}",
                    params={"fields": "status,country,countryCode,region,city,isp,org,as,query"}
                )
                response.raise_for_status()
                data = response.json()

                if data.get("status") == "fail":
                    return {"error": "IPAPI lookup failed"}

                return {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "as_number": data.get("as"),
                }

        except httpx.TimeoutException:
            return {"error": "IPAPI request timeout"}
        except httpx.HTTPStatusError as e:
            return {"error": f"IPAPI HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"IPAPI error: {str(e)}"}


class ThreatAPIClient:
    """Unified client for all threat intelligence APIs"""

    def __init__(self):
        self.abuseipdb = AbuseIPDBClient()
        self.ipqualityscore = IPQualityScoreClient()
        self.ipapi = IPAPIClient()

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address against all available threat intelligence sources.

        Args:
            ip_address: IP address to check

        Returns:
            Dict containing aggregated data from all sources
        """
        # Run all API calls concurrently
        abuseipdb_task = self.abuseipdb.check_ip(ip_address)
        ipqualityscore_task = self.ipqualityscore.check_ip(ip_address)
        ipapi_task = self.ipapi.check_ip(ip_address)

        # Wait for all results
        import asyncio
        abuseipdb_data, ipqs_data, ipapi_data = await asyncio.gather(
            abuseipdb_task,
            ipqualityscore_task,
            ipapi_task,
            return_exceptions=True
        )

        return {
            "abuseipdb": abuseipdb_data if not isinstance(abuseipdb_data, Exception) else {"error": str(abuseipdb_data)},
            "ipqualityscore": ipqs_data if not isinstance(ipqs_data, Exception) else {"error": str(ipqs_data)},
            "ipapi": ipapi_data if not isinstance(ipapi_data, Exception) else {"error": str(ipapi_data)},
        }