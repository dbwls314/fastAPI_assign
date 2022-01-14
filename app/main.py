import bcrypt,jwt
from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from typing import Optional
from sqlmodel import Session, select
from starlette.middleware.cors import CORSMiddleware

from db import engine, create_db_and_tables, SECRET_KEY, ALGORITHM
from models.models import User, UpdateUserRequest, Token, LoginRequest

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/users/signup", status_code=status.HTTP_201_CREATED)
def create_user(user:User) -> dict:
    with Session(engine) as session:
        if session.exec(select(User).filter(User.email == user.email)).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "user already exists")

        user.password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode() 
        session.add(user)
        session.commit()
        session.close()
        return {"message" : "create user"}
 
@app.post("/users/login", response_model=Token, status_code=status.HTTP_200_OK)
async def login_for_access_token(login_request: LoginRequest) -> dict:
    user = _authenticate_user(email=login_request.email, password=login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
   
    access_token = _create_access_token(email=user.email)
    return {"access_token": access_token, "token_type": "bearer"}

@app.patch("/users/{user_id}", status_code=status.HTTP_200_OK)
def update_user(user_id : int, user:UpdateUserRequest) -> dict:
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id == user_id)).one()
        
        if not user:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "user not exist")

        session.add(user) 
        session.commit()
        session.refresh(user)
        return {"message" : "user update"}

@app.delete("/users/{user_id}")
def delete_user(user_id : int):
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "user not exist")
        else:
            session.delete(user)
            session.commit()
        return status.HTTP_204_NO_CONTENT

@app.on_event("startup")
def startup_event():
    create_db_and_tables()

def _authenticate_user(email: str, password: str) -> Optional[User]:
    with Session(engine) as session:
        user = session.exec(select(User).filter(User.email == email)).first()

    if not user:
        return None
    if not _check_password(password, user.password):
        return None
    return user

def _create_access_token(email: str) -> str:
    payload = {"email": email}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def _check_password(password:str, db_password:str) -> bool:
    checkpw = bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8'))
    return checkpw 
    