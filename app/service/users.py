import bcrypt
from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from sqlmodel import Session, select
from db import engine
from models.models import User, UserUpdate
from typing import Dict

app = FastAPI

def create_user(user:User) -> Dict: 
    with Session(engine) as session:
        if session.exec(select(User).filter(User.email == user.email)).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "user already exist")
    
        user.password = _hash_passwrod(user.password)
        session.add(user)
        session.commit()
        session.close()
        return {"message" : "create user"}

def update_user(user_id : int, user_update:UserUpdate) -> Dict:
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id == user_id)).one()
        
        if not user:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "user not exist")

        user.username = user_update.username
        user.email = user_update.email
        user.password = _hash_passwrod(user_update.password)

        session.add(user) 
        session.commit()
        session.refresh(user)
        return {"message" : "user update"}

def remove_user(user_id : int):
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "user not exist")

        session.delete(user)
        session.commit()
        return status.HTTP_204_NO_CONTENT
        
def _hash_passwrod(input_password):
    return bcrypt.hashpw(input_password.encode('utf-8'), bcrypt.gensalt()).decode()
            
