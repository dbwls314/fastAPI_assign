from base64 import encode
from typing import Optional
import bcrypt,jwt
from fastapi.param_functions import Depends
from fastapi.exceptions import HTTPException
from fastapi import FastAPI, status
from pydantic.main import BaseModel
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

#6 input_password, hashed_password 인자를 받아서 pwd_context를 통해서 bcrypt함
# def verify_password(input_password, hashed_password):
#     # return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
#     return pwd_context.verify(input_password, hashed_password)


# def get_password_hash(password):
#     return pwd_context.hash(password)

#4 username을 인자로 받아서 db에 있는지 확인작업
# def get_user(username: str):
#     print(f"username:{username}")
#     with Session(engine) as session:
#         # db_user = session.exec(select(User)).all()
#         user = session.exec(select(User).filter(User.username == username)).first()
#         # print(f"db_user:{db_user}")
#         print(f"user:{user}")
#         if username in user:
#             user_dict = user[username]
#             # user_dict = username in session.exec(select(User)).all()[username]
#     # if username in db:
#     #     user_dict = db[username]
#             print(f"user_dict:{user_dict}")
#             return UserInDB(**user_dict)

#2 username과 password 인자로 받음
# def authenticate_user(username: str, password: str):
#     #3 
#     print(f"username:{username}")
#     user = get_user(username)
#     print(f"user:{user}")
#     if not user:
#         return False
#     #5 get_user 통해서 username이 db에 잇다면 user를 password 확인작업
#     if not verify_password(password, user.hashed_password):
#         print(f"user.hashed_password:{user.hashed_password}")
#         return False
#     #7 비밀번호까지 db확인되면, username 정보가 있는 user을 정보를 받음
#     return user

# def authenticate_user(username: str, password: str):
#     #3 
#     print(f"username:{username}")
#     with Session(engine) as session:
#     # db_user = session.exec(select(User)).all()
#         user = session.exec(select(User).filter(User.username == username)).first()
#     if not user:
#         return False
#     #5 get_user 통해서 username이 db에 잇다면 user를 password 확인작업
#     if not pwd_context.hash(password):
#         return False
#     # if not verify_password(password, user.hashed_password):
#     #     print(f"user.hashed_password:{user.hashed_password}")
#     #     return False
#     #7 비밀번호까지 db확인되면, username 정보가 있는 user을 정보를 받음
#     return user

# def authenticate_user(username: str, password: str):
#     print(f"username:{username}")
#     with Session(engine) as session:
#         user = session.exec(select(User).filter(User.username == username)).first()
#     if not user:
#         return False
#     if not pwd_context.hash(password):
#         return False
#     return user

# def fake_decode_token(token):
#     user = get_user(fake_users_db, token)
#     return user


# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     user = fake_decode_token(token)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     return user


# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user


# def create_access_token(data: dict):
#     to_encode = data.copy()
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# #token를 발급받은 유저인지 확인하는 방법
# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception
#     user = get_user(username=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user

# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    #1 : authenticate_user
    user = authenticate_user(form_data.username, form_data.password)
    print(f"user:{user}")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
   
    access_token = create_access_token(data={"username": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

def authenticate_user(username: str, password: str):
    print(f"username:{username}")
    with Session(engine) as session:
        user = session.exec(select(User).filter(User.username == username)).first()
    if not user:
        return False
    if not pwd_context.hash(password):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
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
    
         
    user = get_user(username=token_data.username) 
    if user is None:
        raise credentials_exception
    return user


# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     return current_user