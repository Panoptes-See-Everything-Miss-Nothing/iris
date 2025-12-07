def create_version_dictionary(data):
    source = data.get("source")

    cvss_data = data.get("cvssData")
    version = cvss_data.get("version")
    base_score = cvss_data.get("baseScore")
    access_vector = cvss_data.get("accessVector")
    access_complexity = cvss_data.get("accessComplexity")
    authentication = cvss_data.get("authentication")
    confidentiality_impact = cvss_data.get("confidentialityImpact")
    integrity_impact = cvss_data.get("integrityImpact")
    availability_impact = cvss_data.get("availabilityImpact")

    base_severity = data.get("baseSeverity")
    exploitabilityScore = data.get("exploitabilityScore")
    impactScoredata = data.get("impactScore")

    return {
        "source": source,
        "version": version,
        "base_score": base_score,
        "access_vector": access_vector.lower() if access_vector else None,
        "access_complexity": access_complexity.lower() if access_complexity else None,
        "authentication": authentication.lower() if authentication else None,
        "confidentiality_impact": (
            confidentiality_impact.lower() if confidentiality_impact else None
        ),
        "integrity_impact": integrity_impact.lower() if integrity_impact else None,
        "availability_impact": (
            availability_impact.lower() if availability_impact else None
        ),
        "base_severity": base_severity.lower() if base_severity else None,
        "exploitabilityScore": exploitabilityScore,
        "impactScoredata": impactScoredata,
    }
