import json
import os
from typing import Dict, Any, Optional
from groq import Groq
from dotenv import load_dotenv
from app.models import ThreatData, AIAnalysis

load_dotenv()


class LLMService:
    """
    Service for AI-powered threat analysis using Groq LLM (Llama 3).
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=self.api_key) if self.api_key else None
        self.model = "llama-3.1-70b-versatile"

    def _build_prompt(self, ip_address: str, threat_data: ThreatData) -> str:
        """
        Build a comprehensive prompt for the LLM with threat intelligence data.

        Args:
            ip_address: IP address being analyzed
            threat_data: Aggregated threat data

        Returns:
            Formatted prompt string
        """
        prompt = f"""You are a cybersecurity threat analyst. Analyze the following IP address threat intelligence data and provide a risk assessment.

IP Address: {ip_address}

Threat Intelligence Data:
- Hostname: {threat_data.hostname or 'Unknown'}
- ISP: {threat_data.isp or 'Unknown'}
- Country: {threat_data.country or 'Unknown'}
- Abuse Score: {threat_data.abuse_score if threat_data.abuse_score is not None else 'N/A'} (0-100, higher = more malicious)
- Recent Abuse Reports: {threat_data.recent_reports if threat_data.recent_reports is not None else 'N/A'}
- VPN Detected: {threat_data.vpn_detected if threat_data.vpn_detected is not None else 'Unknown'}
- Proxy Detected: {threat_data.proxy_detected if threat_data.proxy_detected is not None else 'Unknown'}
- Fraud Score: {threat_data.fraud_score if threat_data.fraud_score is not None else 'N/A'} (0-100, higher = more suspicious)
- Tor Exit Node: {threat_data.is_tor if threat_data.is_tor is not None else 'Unknown'}

Based on this data, provide a comprehensive risk assessment in the following JSON format:
{{
  "risk_level": "Low|Medium|High",
  "risk_analysis": "2-3 sentence explanation of the risk level based on the data",
  "recommendations": ["recommendation1", "recommendation2", "recommendation3"]
}}

Guidelines:
- Low Risk: Abuse score < 20, fraud score < 30, no VPN/proxy/Tor, minimal reports
- Medium Risk: Abuse score 20-60, fraud score 30-75, VPN/proxy detected, some reports
- High Risk: Abuse score > 60, fraud score > 75, Tor detected, many reports

Provide ONLY the JSON response, no additional text."""

        return prompt

    async def analyze_threats(self, ip_address: str, raw_threat_data: Dict[str, Any]) -> AIAnalysis:
        """
        Analyze threat data using Groq LLM and generate risk assessment.

        Args:
            ip_address: IP address being analyzed
            raw_threat_data: Raw threat data from APIs (needs aggregation)

        Returns:
            AIAnalysis object with risk assessment
        """
        # Import aggregator here to avoid circular imports
        from app.services.aggregator import ThreatDataAggregator

        # Aggregate the raw data first
        threat_data = ThreatDataAggregator.aggregate({
            **raw_threat_data,
            "ip_address": ip_address
        })

        # Try LLM analysis first
        if self.client:
            try:
                analysis = await self._llm_analysis(ip_address, threat_data)
                if analysis:
                    return analysis
            except Exception as e:
                print(f"LLM analysis failed: {e}, falling back to rule-based")

        # Fallback to rule-based analysis
        return self._rule_based_analysis(threat_data)

    async def _llm_analysis(self, ip_address: str, threat_data: ThreatData) -> Optional[AIAnalysis]:
        """
        Perform LLM-based analysis using Groq.

        Args:
            ip_address: IP address being analyzed
            threat_data: Aggregated threat data

        Returns:
            AIAnalysis object or None if failed
        """
        try:
            prompt = self._build_prompt(ip_address, threat_data)

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity threat analyst. Respond only with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=500,
                response_format={"type": "json_object"}
            )

            # Parse LLM response
            content = response.choices[0].message.content
            analysis_data = json.loads(content)

            return AIAnalysis(
                risk_level=analysis_data.get("risk_level", "Medium"),
                risk_analysis=analysis_data.get("risk_analysis", "Unable to determine risk"),
                recommendations=analysis_data.get("recommendations", [])
            )

        except Exception as e:
            print(f"LLM analysis error: {e}")
            return None

    def _rule_based_analysis(self, threat_data: ThreatData) -> AIAnalysis:
        """
        Fallback rule-based risk analysis when LLM is unavailable.

        Args:
            threat_data: Aggregated threat data

        Returns:
            AIAnalysis object
        """
        # Calculate risk score
        risk_score = 0
        factors = []

        # Abuse score analysis
        abuse_score = threat_data.abuse_score or 0
        if abuse_score > 60:
            risk_score += 40
            factors.append(f"high abuse score ({abuse_score})")
        elif abuse_score > 20:
            risk_score += 20
            factors.append(f"moderate abuse score ({abuse_score})")

        # Recent reports
        reports = threat_data.recent_reports or 0
        if reports > 10:
            risk_score += 20
            factors.append(f"{reports} recent abuse reports")
        elif reports > 0:
            risk_score += 10

        # Fraud score
        fraud_score = threat_data.fraud_score or 0
        if fraud_score > 75:
            risk_score += 30
            factors.append(f"high fraud score ({fraud_score})")
        elif fraud_score > 30:
            risk_score += 15

        # Tor detection
        if threat_data.is_tor:
            risk_score += 25
            factors.append("Tor exit node detected")

        # VPN/Proxy detection
        if threat_data.vpn_detected:
            risk_score += 10
            factors.append("VPN detected")
        if threat_data.proxy_detected:
            risk_score += 10
            factors.append("proxy detected")

        # Determine risk level
        if risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Build analysis text
        if factors:
            analysis = f"Risk assessment based on: {', '.join(factors)}. Overall risk score: {risk_score}/100."
        else:
            analysis = "No significant threat indicators detected. IP appears to be legitimate based on available data."

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, threat_data)

        return AIAnalysis(
            risk_level=risk_level,
            risk_analysis=analysis,
            recommendations=recommendations
        )

    def _generate_recommendations(self, risk_level: str, threat_data: ThreatData) -> list:
        """Generate security recommendations based on risk level and threat data."""
        recommendations = []

        if risk_level == "High":
            recommendations.append("Block or restrict access from this IP address immediately")
            recommendations.append("Review recent activity from this IP for signs of compromise")
            recommendations.append("Enable enhanced monitoring and logging for this IP")
            if threat_data.is_tor:
                recommendations.append("Consider blocking all Tor exit nodes")
        elif risk_level == "Medium":
            recommendations.append("Monitor activity from this IP address closely")
            recommendations.append("Implement rate limiting for requests from this IP")
            recommendations.append("Consider additional authentication for this IP")
            if threat_data.vpn_detected or threat_data.proxy_detected:
                recommendations.append("Verify legitimate business need for VPN/proxy usage")
        else:
            recommendations.append("Maintain standard security protocols")
            recommendations.append("Continue routine monitoring")
            recommendations.append("No immediate action required")

        return recommendations
