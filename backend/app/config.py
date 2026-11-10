from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuração lida de variáveis de ambiente (arquivo .env via docker compose)."""

    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = "postgresql+psycopg://auditoria:auditoria@db:5432/auditoria"

    # Segredos (gerados pelo setup.ps1)
    jwt_secret: str
    master_key: str  # 32 bytes em base64 - chave mestra (KEK) da criptografia de campos
    master_key_version: int = 1
    access_token_minutes: int = 30

    # Usuários iniciais
    admin_username: str = "admin"
    admin_password: str
    seed_demo_users: bool = True
    demo_password: str = ""

    # Inteligência artificial: gemini | ollama | none
    ai_provider: str = "none"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_embedding_model: str = "gemini-embedding-001"
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_embedding_model: str = "nomic-embed-text"
    ai_pseudonymize: bool = True
    ai_max_per_cycle: int = 5
    ai_min_interval_seconds: float = 6.0
    ai_confidence_threshold: float = 0.7

    # Coleta contínua
    collect_interval_minutes: int = 5
    enabled_collectors: str = "simulador"  # simulador,active_directory,wazuh

    # Active Directory (coletor real - opcional)
    ad_server: str = ""
    ad_use_ssl: bool = True
    ad_user: str = ""
    ad_password: str = ""
    ad_base_dn: str = ""

    # Wazuh (coletor real - opcional)
    wazuh_url: str = ""
    wazuh_user: str = ""
    wazuh_password: str = ""
    wazuh_verify_tls: bool = False


settings = Settings()
