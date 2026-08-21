import ipaddress
import hashlib
import requests
from typing import Dict, Any
from core.config import settings
from core.logger import logger

# Cache for resolved IPs
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

# Simulated locations pool for local testing (RFC 1918 / Loopback)
SIMULATED_POOLS = [
    {"country": "United States", "country_code": "US", "city": "Ashburn", "lat": 39.0437, "lon": -77.4875, "org": "Amazon Data Services", "asn": "AS16509"},
    {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "org": "Hetzner Online GmbH", "asn": "AS24940"},
    {"country": "Japan", "country_code": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "org": "NTT Communications", "asn": "AS4713"},
    {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278, "org": "DigitalOcean LLC", "asn": "AS14061"},
    {"country": "Singapore", "country_code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "org": "OVH SAS", "asn": "AS16276"},
    {"country": "Brazil", "country_code": "BR", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "org": "Claro Telecom", "asn": "AS28573"},
    {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "org": "Telstra Corporation", "asn": "AS1221"},
    {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "org": "Leaseweb Global", "asn": "AS60781"},
    {"country": "South Korea", "country_code": "KR", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "org": "Korea Telecom", "asn": "AS4766"},
    {"country": "Canada", "country_code": "CA", "city": "Toronto", "lat": 43.6532, "lon": -79.3832, "org": "Rogers Communications", "asn": "AS812"},
]

def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return True

def resolve_geoip(ip: str) -> Dict[str, Any]:
    """
    Resolve IP geolocation using cache, local simulation (for LAN/loopback), 
    or external GeoIP API for live public IPs.
    """
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    # Handle local / private IPs with deterministic simulated telemetry
    if is_private_ip(ip):
        # Generate stable pseudo-random assignment based on IP hash
        idx = int(hashlib.md5(ip.encode()).hexdigest(), 16) % len(SIMULATED_POOLS)
        loc = SIMULATED_POOLS[idx].copy()
        loc["is_simulated"] = True
        loc["org"] = f"{loc['org']} (Local Lab Host)"
        _GEO_CACHE[ip] = loc
        return loc

    # Real public IP query with fallback
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,org,as", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "city": data.get("city", "Unknown"),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "is_simulated": False
                }
                _GEO_CACHE[ip] = result
                return result
    except Exception as e:
        logger.debug(f"GeoIP query failed for {ip}: {e}")

    fallback = {
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "org": "Unknown ISP",
        "asn": "Unknown",
        "is_simulated": False
    }
    _GEO_CACHE[ip] = fallback
    return fallback
