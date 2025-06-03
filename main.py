# backend/main.py

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from jose import JWTError, jwt
from datetime import datetime, timedelta
import databases
import sqlalchemy
import io
import pandas as pd
import os

# --- CONFIGURAÇÕES ---

DATABASE_URL = os.getenv("SUPABASE_DB_URL")  # ex: postgresql://user:pass@host:port/dbname
SUPABASE_API_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")  # chave serviço supabase
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "changeme123")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

# Usuários fixos (para login simples)
USERS_DB = {
    "admin": {"username": "admin", "password": "admin123", "role": "admin"},
    "funcionario": {"username": "funcionario", "password": "func123", "role": "funcionario"},
}

# --- SETUP DATABASE & TABLES ---

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

usuarios = sqlalchemy.Table(
    "usuarios",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True, index=True),
    sqlalchemy.Column("hashed_password", sqlalchemy.String),
    sqlalchemy.Column("role", sqlalchemy.String),
)

base_excel = sqlalchemy.Table(
    "base_excel",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("pop", sqlalchemy.String),
    sqlalchemy.Column("chassi", sqlalchemy.String),
    sqlalchemy.Column("placa", sqlalchemy.String),
    sqlalchemy.Column("olt", sqlalchemy.String),
    sqlalchemy.Column("portas", sqlalchemy.Integer),
    sqlalchemy.Column("id_cto", sqlalchemy.String),
    sqlalchemy.Column("cidade", sqlalchemy.String),
    sqlalchemy.Column("caminho_rede", sqlalchemy.String),
)

configuracoes = sqlalchemy.Table(
    "configuracoes",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("chave_google_maps", sqlalchemy.String),
)

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

# --- MODELS ---

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class User(BaseModel):
    username: str
    role: str

class UserInDB(User):
    hashed_password: str

# --- AUTENTICAÇÃO ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    # Como senha é fixa, não vamos hashear (para simplificar)
    return plain_password == hashed_password

def get_user(username: str):
    user = USERS_DB.get(username)
    if user:
        return UserInDB(**user, hashed_password=user["password"])
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Não autorizado", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# --- APP SETUP ---

app = FastAPI(title="App Unificado Cliente")

# CORS liberado para qualquer frontend (ajuste se precisar restringir)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ROTAS ---

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Upload da base Excel e substituição da tabela
@app.post("/upload-base-excel")
async def upload_base_excel(file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado")

    content = await file.read()
    try:
        df = pd.read_excel(io.BytesIO(content))

        # Colunas essenciais
        colunas_essenciais = ["POP", "CHASSI", "PLACA", "OLT", "PORTAS", "ID CTO", "CIDADE"]
        if not all(col in df.columns for col in colunas_essenciais):
            raise HTTPException(status_code=400, detail=f"Colunas essenciais ausentes. Devem conter: {colunas_essenciais}")

        # Montar coluna CAMINHO_REDE
        df["CAMINHO_REDE"] = df["POP"].astype(str) + " / " + df["CHASSI"].astype(str) + " / " + df["PLACA"].astype(str) + " / " + df["OLT"].astype(str)

        # Limpar tabela base_excel antes
        query_delete = base_excel.delete()
        await database.execute(query_delete)

        # Inserir dados
        for _, row in df.iterrows():
            query_insert = base_excel.insert().values(
                pop=row["POP"],
                chassi=row["CHASSI"],
                placa=row["PLACA"],
                olt=row["OLT"],
                portas=int(row["PORTAS"]),
                id_cto=row["ID CTO"],
                cidade=row["CIDADE"],
                caminho_rede=row["CAMINHO_REDE"],
            )
            await database.execute(query_insert)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao processar arquivo Excel: {str(e)}")

    return {"msg": "Base Excel importada com sucesso"}

# Salvar ou atualizar chave Google Maps
@app.post("/configurar-google-maps")
async def configurar_google_maps(chave: str = Form(...), current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado")

    query = await database.fetch_one(sqlalchemy.select([configuracoes]).limit(1))
    if query:
        update = configuracoes.update().values(chave_google_maps=chave).where(configuracoes.c.id == query["id"])
        await database.execute(update)
    else:
        insert = configuracoes.insert().values(chave_google_maps=chave)
        await database.execute(insert)
    return {"msg": "Chave Google Maps salva com sucesso"}

# Buscar dados (exemplo de busca simples: buscar por ID CTO)
@app.get("/buscar-por-cto/{id_cto}")
async def buscar_por_cto(id_cto: str, current_user: User = Depends(get_current_active_user)):
    query = base_excel.select().where(base_excel.c.id_cto == id_cto)
    rows = await database.fetch_all(query)
    results = [dict(row) for row in rows]
    if not results:
        raise HTTPException(status_code=404, detail="CTO não encontrada")
    return results

# Buscar dados por cidade (exemplo)
@app.get("/buscar-por-cidade/{cidade}")
async def buscar_por_cidade(cidade: str, current_user: User = Depends(get_current_active_user)):
    query = base_excel.select().where(base_excel.c.cidade == cidade)
    rows = await database.fetch_all(query)
    return [dict(row) for row in rows]

# Buscar chave Google Maps
@app.get("/google-maps-key")
async def get_google_maps_key(current_user: User = Depends(get_current_active_user)):
    query = await database.fetch_one(sqlalchemy.select([configuracoes]).limit(1))
    return {"chave": query["chave_google_maps"] if query else None}
