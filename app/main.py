from base64 import encode
from typing import Optional
import bcrypt,jwt
from fastapi.param_functions import Depends
from fastapi.exceptions import HTTPException
from fastapi import FastAPI, status
from pydantic import BaseModel
from sqlmodel import Session, select
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_400_BAD_REQUEST

from db import engine, create_db_and_tables, SECRET_KEY, ALGORITHM
from models.models import User, UserUpdate

# session = Session(bind = engine)
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# @app.post("/users/signup", status_code=status.HTTP_201_CREATED)
# def create_user(username:str, email:str, password:str):
#     print(username)
#     db_user = User()

#     db_user.username = username
#     db_user.email = email
#     db_user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode() 
#     # user.password = password
#     session.add(db_user)
#     session.commit()
#     return {"message" : "create user"}

@app.post("/users/signup", status_code=status.HTTP_201_CREATED)
def create_user(user:User):
    with Session(engine) as session:
        if session.exec(select(User).filter(User.email == user.email)).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "user is exist")

        user.password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode()  
        session.add(user)
        session.commit()
        return {"message" : "create user"}

# @app.post("/users/login")
# def get_user(email:str, password:str):
#     print(f"email:{email}")
#     print(f"password:{password}")
#     with Session(engine) as session:
#         print(1)
#         db_user = session.exec(select(User).filter(User.email == email, User.password == password)).first()
#         print(f"db_user:{db_user}")
#         if not db_user:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = "user not exist")
#         if bcrypt.checkpw(password.encode('utf-8'), db_user.password.encode('utf-8')):
#             token = jwt.encode({'id' : User.id}, SECRET_KEY, ALGORITHM)
#         return token
 
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


#-------
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt

# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "fakehashedsecret",
#         "disabled": False,
#     },
#     "alice": {
#         "username": "alice",
#         "full_name": "Alice Wonderson",
#         "email": "alice@example.com",
#         "hashed_password": "fakehashedsecret2",
#         "disabled": True,
#     },
# }

# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
#         "disabled": False,
#     }
# }

# def fake_hash_password(password: str):
#     return "fakehashed" + password

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#fastapi 에서 bearer Token을 이용하는 것
oauth2_scheme = OAuth2PasswordBearer(tokenUrl ="token")

# class User(BaseModel):
#     username:str
#     email:Optional[str] = None
#     full_name: Optional[str] = None
#     disabled: Optional[str] = None
#     password: Optional[str] = None

class UserInDB(User):
    hashed_password : str

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str


#form을 이용하는 방법 / jwt 방법도 있고, 여러가지 있음
@app.post("/users/login", response_model=Token)
async def login_for_access_token(login_request: LoginRequest):
    user = authenticate_user(email=login_request.email, password=login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
   
    access_token = create_access_token(email=user.email)
    return {"access_token": access_token, "token_type": "bearer"}

def authenticate_user(email: str, password: str) -> User:
    with Session(engine) as session:
        user = session.exec(select(User).filter(User.email == email)).first()
    if not user:
        return None
    # if not pwd_context.hash(password):
    #     return None
    return user

def create_access_token(email: str):
    payload = {"email": email}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#token를 발급받은 유저인지 확인하는 방법
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None: 
            raise credentials_exception     
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    with Session(engine) as session:
        user = session.exec(select(User).filter(User.username == token_data.username)).first()
    if user in None:
        raise credentials_exception
    return user

# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     return current_user