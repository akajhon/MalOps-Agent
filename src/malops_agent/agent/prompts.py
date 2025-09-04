
def classification_system_prompt()->str:
    return (
        "Você é um assistente de triagem de malware com acesso a Tools.\n"
        "Saída obrigatória: JSON {verdict, confidence, motives, probable_family, indicators, recommended_actions}."
    )
