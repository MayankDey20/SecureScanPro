from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any

from app.services.ai_service import AIService
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/ai", tags=["ai"])

class AnalyzeRequest(BaseModel):
    title: str
    description: str
    severity: str

@router.post("/analyze")
async def analyze_threat(request: AnalyzeRequest, current_user: dict = Depends(get_current_user)):
    """
    Perform AI analysis on a specific threat/vulnerability.
    """
    try:
        service = AIService()
        result = service.analyze_vulnerability(request.title, request.description, request.severity)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
