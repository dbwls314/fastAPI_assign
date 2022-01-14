import bcrypt,jwt
from fastapi import FastAPI, status
from fastapi.exceptions import HTTPException
from sqlmodel import Session, select
from starlette.middleware.cors import CORSMiddleware

from db import engine, create_db_and_tables, SECRET_KEY, ALGORITHM
from models.models import User, UserUpdate, Token, LoginRequest

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/users/signup", status_code=status.HTTP_201_CREATED)
def create_user(user:User):
    with Session(engine) as session:
        if session.exec(select(User).filter(User.email == user.email)).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "user is exist")

        user.password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode() 
        session.add(user)
        session.commit()
        session.close()
        return {"message" : "create user"}
 
@app.post("/users/login", response_model=Token)
async def login_for_access_token(login_request: LoginRequest):
    user = authenticate_user(email=login_request.email, password=login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email",
            headers={"WWW-Authenticate": "Bearer"},
        )
   
    access_token = create_access_token(email=user.email)

    return {"access_token": access_token, "token_type": "bearer"}

def authenticate_user(email: str, password: str):
    with Session(engine) as session:
        user = session.exec(select(User).filter(User.email == email)).first()

    if not user:
        return None
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return None
    return user

def create_access_token(email: str):
    payload = {"email": email}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.patch("/users/{user_id}")
def update_user(user_id : int, user:UserUpdate):
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.id == user_id)).one()
        
        if not db_user:
            raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "user not exist")

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
            raise HTTPException(status_code = status.HTTP_204_NO_CONTENT, detail = "no content")
        else:
            session.delete(user)
            session.commit()
        return {}

@app.on_event("startup")
def startup_event():
    create_db_and_tables()
