import bcrypt, jwt

from sqlmodel import Session, select
from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from typing import Optional, Dict
from jose import JWTError

from models.models import User, LoginRequest
from db import engine, SECRET_KEY, ALGORITHM

app = FastAPI

def get_access_token_after_succesful_login(login_request: LoginRequest) -> Dict:
    user = _authenticate_user(email=login_request.email, password=login_request.password)
    if not user:
        raise _incorrect_account_exception()
   
    access_token = _create_access_token(email=user.email)
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token:str) -> Optional[User]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        email: str = payload.get("email")
        
        if email is None:
            raise _credentials_exception

        with Session(engine) as session:
            user = session.exec(select(User).filter(User.email == email)).first()
            if user is None:
                raise _credentials_exception
            return user
    except JWTError:
        raise _credentials_exception

def _incorrect_account_exception():
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password"
    )

def _credentials_exception():
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="could not validate credentials"
    )

def _authenticate_user(email: str, password: str) -> Optional[User]:
    with Session(engine) as session:
        user = session.exec(select(User).filter(User.email == email)).first()

    if not user:
        return None
    if not _check_password(password, user.password):
        return None
    return user

def _create_access_token(email: str) -> str:
    return jwt.encode({"email": email}, SECRET_KEY, algorithm=ALGORITHM)

def _check_password(password:str, db_password:str) -> bool:
    UTF_8 = 'utf-8'
    return bcrypt.checkpw(password.encode(UTF_8), db_password.encode(UTF_8))

