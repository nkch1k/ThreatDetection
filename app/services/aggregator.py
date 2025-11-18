from typing import Dict, Any, Optional
from app.models import ThreatData


class ThreatDataAggregator:
    """
    Aggregates and normalizes threat intelligence data from multiple sources.
    """

    @staticmethod
    def aggregate(raw_data: Dict[str, Any]) -> ThreatData:
        """
        Normalize and combine data from multiple threat intelligence sources.

        Args:
            raw_data: Raw API responses from threat intelligence sources
                Expected keys: "abuseipdb", "ipqualityscore", "ipapi"

        Returns:
            ThreatData object with normalized and aggregated information
        """
        abuseipdb = raw_data.get("abuseipdb", {})
        ipqs = raw_data.get("ipqualityscore", {})
        ipapi = raw_data.get("ipapi", {})

        # Extract IP address (should be consistent across sources)
        ip_address = raw_data.get("ip_address", "unknown")

        # Aggregate geolocation data (prefer IPAPI, fallback to others)
        country = (
            ipapi.get("country") or
            abuseipdb.get("country_code") or
            ipqs.get("country_code")
        )

        # Aggregate ISP information
        isp = (
            ipapi.get("isp") or
            abuseipdb.get("isp") or
            ipqs.get("isp")
        )

        # Extract hostname data
        hostnames = abuseipdb.get("hostnames", [])
        hostname = hostnames[0] if hostnames else abuseipdb.get("domain")

        # Aggregate threat scores
        abuse_score = abuseipdb.get("abuse_score")
        recent_reports = abuseipdb.get("recent_reports")

        # Aggregate proxy/VPN detection
        vpn_detected = ipqs.get("vpn")
        proxy_detected = ipqs.get("proxy")
        fraud_score = ipqs.get("fraud_score")
        is_tor = ipqs.get("tor")

        return ThreatData(
            ip_address=ip_address,
            hostname=hostname,
            isp=isp,
            country=country,
            abuse_score=abuse_score,
            recent_reports=recent_reports,
            vpn_detected=vpn_detected,
            proxy_detected=proxy_detected,
            fraud_score=fraud_score,
            is_tor=is_tor
        )

    @staticmethod
    def has_errors(raw_data: Dict[str, Any]) -> bool:
        """
        Check if any of the API sources returned errors.

        Args:
            raw_data: Raw API responses

        Returns:
            True if all sources returned errors, False otherwise
        """
        sources = ["abuseipdb", "ipqualityscore", "ipapi"]
        error_count = sum(
            1 for source in sources
            if "error" in raw_data.get(source, {})
        )

        # Return True only if ALL sources failed
        return error_count == len(sources)

    @staticmethod
    def get_working_sources(raw_data: Dict[str, Any]) -> list:
        """
        Get list of sources that successfully returned data.

        Args:
            raw_data: Raw API responses

        Returns:
            List of source names that returned valid data
        """
        sources = ["abuseipdb", "ipqualityscore", "ipapi"]
        return [
            source for source in sources
            if "error" not in raw_data.get(source, {})
        ]