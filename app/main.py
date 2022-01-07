import bcrypt
from fastapi.exceptions import HTTPException
from fastapi import FastAPI
from sqlmodel import Session, select
from starlette.middleware.cors import CORSMiddleware

from db import engine, create_db_and_tables
from .models.models import User, UserUpdate

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/users")
def create_user(user:User): 
    with Session(engine) as session:
        if session.exec(select(User).filter(User.email == user.email)).first():
            raise HTTPException(status_code = 400, detail = "email exist")

        user.password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode()  
        session.add(user)
        session.commit()
        return {"message" : "create user"}

@app.get("/users/{user_id}")
def get_user(user_id : int):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id == user_id)).first()
        if not user:
            raise HTTPException(status_code = 404, detail = "user not exist")
        return {"result" : user}

@app.patch("/users/{user_id}")
def update_user(user_id : int, user:UserUpdate):
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.id == user_id)).one()
        
        if not db_user:
            raise HTTPException(status_code = 404, detail = "user not exist")

        if user.email:
            db_user.email = user.email

        if user.password:
            db_user.password = user.password

        session.add(db_user) 
        session.commit()
        session.refresh(db_user)
        return {"message" : "user update"}

@app.delete("/users/{user_id}")
def delete_user(user_id : int):
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code = 204, detail = "no content")
        else:
            session.delete(user)
            session.commit()
        return {}

@app.on_event("startup")
def startup_event():
    create_db_and_tables()
