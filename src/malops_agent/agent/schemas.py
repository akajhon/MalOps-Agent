
from typing import List, Optional, Dict
from pydantic import BaseModel, Field

class Indicators(BaseModel):
    hashes: Optional[Dict[str, str]] = None
    imports: Optional[List[str]] = None
    urls: Optional[List[str]] = None
    domains: Optional[List[str]] = None
    ipv4s: Optional[List[str]] = None
    wallets: Optional[Dict[str, list]] = None
    strings: Optional[List[str]] = None

class Verdict(BaseModel):
    verdict: str = Field(..., description="malicious|suspicious|benign")
    veredict: str
    confidence: float
    motives: List[str]
    probable_family: Optional[str] = None
    indicators: Indicators
    recommended_actions: List[str]
