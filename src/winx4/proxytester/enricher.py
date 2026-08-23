from __future__ import annotations

import maxminddb

from .models import GeoInfo
from .plugins import enricher as register_enricher


@register_enricher("geolite2")
class GeoEnricher:
    def __init__(self, city_db: str | None = None, asn_db: str | None = None):
        self._city = maxminddb.open_database(city_db) if city_db else None
        self._asn = maxminddb.open_database(asn_db) if asn_db else None

    def close(self) -> None:
        if self._city:
            self._city.close()
        if self._asn:
            self._asn.close()

    def enrich(self, ip: str) -> GeoInfo | None:
        info = GeoInfo()
        try:
            if self._city:
                rec = self._city.get(ip)
                if rec:
                    city = rec.get("city", {})
                    country = rec.get("country", {})
                    location = rec.get("location", {})
                    subs = rec.get("subdivisions") or []
                    info.city = _name(city)
                    info.country = _name(country)
                    info.country_iso = country.get("iso_code")
                    info.region = _name(subs[0]) if subs else None
                    info.latitude = location.get("latitude")
                    info.longitude = location.get("longitude")
                    info.timezone = location.get("time_zone")
            if self._asn:
                rec = self._asn.get(ip)
                if rec:
                    info.asn = rec.get("autonomous_system_number")
                    info.org = rec.get("autonomous_system_organization")
        except (ValueError, TypeError):
            return None
        if all(v is None for v in (info.country, info.asn)):
            return None
        return info


def _name(d: dict) -> str | None:
    names = d.get("names") or {}
    return names.get("en")
