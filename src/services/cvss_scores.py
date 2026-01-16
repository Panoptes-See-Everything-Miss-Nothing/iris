from src.models.cvss import CVSSv2, CVSSv3


def parse_cvss_v2(cve_id, v2):
    cvss_v2 = CVSSv2(
        cve_id=cve_id,
        version=v2.get("version"),
        base_score=v2.get("baseScore"),
        base_severity=v2.get("baseSeverity"),
        access_vector=v2.get("accessVector"),
        access_complexity=v2.get("accessComplexity"),
        authentication=v2.get("authentication"),
        confidentiality_impact=v2.get("confidentialityImpact"),
        integrity_impact=v2.get("integrityImpact"),
        availability_impact=v2.get("availabilityImpact"),
        exploitability_score=v2.get("exploitabilityScore"),
        impact_score=v2.get("impactScore"),
        vector_string=v2.get("vectorString"),
        # Flags
        ac_insuf_info=v2.get("acInsufInfo"),
        obtain_all_privilege=v2.get("obtainAllPrivilege"),
        obtain_user_privilege=v2.get("obtainUserPrivilege"),
        obtain_other_privilege=v2.get("obtainOtherPrivilege"),
        user_interaction_required=v2.get("userInteractionRequired"),
    )
    return cvss_v2


def parse_cvss_v3(cve_id, v3):
    cvss_v3 = CVSSv3(
        cve_id=cve_id,
        version=v3.get("version"),
        base_score=v3.get("baseScore"),
        base_severity=v3.get("baseSeverity"),
        attack_vector=v3.get("attackVector"),
        attack_complexity=v3.get("attackComplexity"),
        privileges_required=v3.get("privilegesRequired"),
        user_interaction=v3.get("userInteraction"),
        scope=v3.get("scope"),
        confidentiality_impact=v3.get("confidentialityImpact"),
        integrity_impact=v3.get("integrityImpact"),
        availability_impact=v3.get("availabilityImpact"),
        exploitability_score=v3.get("exploitabilityScore"),
        impact_score=v3.get("impactScore"),
        vector_string=v3.get("vectorString"),
    )
    return cvss_v3
