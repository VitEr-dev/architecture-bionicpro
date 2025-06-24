import os
import logging
from pathlib import Path
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from pydantic import BaseModel
import httpx
import json
from jwt.algorithms import RSAAlgorithm

# Настройка логгирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Reports API", version="1.0.0")

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Конфигурация Keycloak
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
REALM = os.getenv("KEYCLOAK_REALM", "reports-realm")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "reports-api")

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
)

class TokenData(BaseModel):
    sub: str
    exp: int
    preferred_username: str
    realm_roles: List[str]

async def get_public_key():
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
            )
            response.raise_for_status()
            jwks = response.json()
            key_data = next(k for k in jwks['keys'] if k.get('kty') == 'RSA')
            return RSAAlgorithm.from_jwk(json.dumps(key_data))
        except Exception as e:
            logger.error(f"Failed to get public key: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to verify credentials"
            )

async def validate_token(token: str = Depends(oauth2_scheme)):
    logger.info(f"Validating token: {token[:20]}...")
    
    try:
        # Получаем kid из заголовка токена
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        # Получаем соответствующий ключ
        public_key = await get_public_key()
        
        # Декодируем токен
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            options={"verify_aud": True},
        )
        
        # Извлекаем роли
        realm_roles = payload.get("realm_access", {}).get("roles", [])
        
        return TokenData(
            sub=payload.get("sub"),
            exp=payload.get("exp"),
            preferred_username=payload.get("preferred_username", ""),
            realm_roles=realm_roles
        )
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")

@app.get("/reports")
async def download_report(token_data: TokenData = Depends(validate_token)):
    # Улучшенная проверка роли с детальным логированием
    logger.info(f"User {token_data.preferred_username} trying to access report. Roles: {token_data.realm_roles}")
    
    if not any(role == "prothetic_user" for role in token_data.realm_roles):
        logger.warning(f"ACCESS DENIED for {token_data.preferred_username}. Roles: {token_data.realm_roles}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Requires prothetic_user role"
        )
    
    file_path = Path("/app/data.csv")
    if not file_path.exists():
        logger.error("Report file not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    logger.info(f"ACCESS GRANTED for {token_data.preferred_username}")
    return FileResponse(
        file_path,
        media_type="text/csv",
        filename="report.csv",
        headers={
            "Content-Disposition": "attachment; filename=report.csv",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.on_event("startup")
async def startup_event():
    logger.info("API service starting...")