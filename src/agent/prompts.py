
def supervisor_prompt()->str:
    return (
        "Você é um assistente de triagem de malware com acesso a Tools.\n"
        "Saída obrigatória: JSON {verdict, confidence, motives, probable_family, indicators, recommended_actions}."
    )

def static_analysis_prompt()->str:
    return (
        """Analyze this comprehensive technical data from a potentially malicious program for professional malware triage:

        === BASIC PE FACTS ===
        SHA256: {sha256}
        File Size: {file_size} bytes
        Architecture: {architecture}
        Compile Timestamp: {compile_timestamp}
        Subsystem: {subsystem}

        === IMPORTS ANALYSIS ===
        {imports_summary}

        === SECTIONS ANALYSIS ===
        {sections_summary}

        === VERSION INFORMATION ===
        {version_summary}

        === STABLE STRINGS (Relevant for Analysis) ===
        {strings_summary}

        === CODE SIGNATURES ===
        {signatures_summary}

        === ADVANCED INDICATORS ===
        {advanced_summary}

        Provide a PROFESSIONAL MALWARE TRIAGE ANALYSIS including:

        1. THREAT ASSESSMENT: Overall risk level (Benign/Low/Medium/High/Critical) with justification
        2. MALWARE FAMILY: Most likely malware family or category based on technical indicators
        3. BEHAVIORAL ANALYSIS: What this malware likely does based on imports, strings, and patterns
        4. KEY INDICATORS: Specific technical indicators that support your assessment
        5. DETECTION EVASION: Any anti-analysis or evasion techniques observed
        6. NETWORK INDICATORS: C2, exfiltration, or network behavior indicators
        7. PERSISTENCE: Likely persistence mechanisms
        8. RECOMMENDATIONS: Specific next steps for analysis and response
        9. CONFIDENCE LEVEL: Your confidence in this assessment (High/Medium/Low)

        Base your analysis ONLY on the technical data provided. Be specific and technical."""
    )