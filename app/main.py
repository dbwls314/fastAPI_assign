import bcrypt,jwt
from fastapi.param_functions import Depends
from fastapi.exceptions import HTTPException
from fastapi import FastAPI, status
from sqlmodel import Session, select
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_400_BAD_REQUEST

from db import engine, create_db_and_tables, SECRET_KEY, ALGORITHM
from models.models import User, UserUpdate

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError
# from models.models import TokenData, UserInDB, Token

session = Session(bind = engine)
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# @app.post("/users/signup", status_code=status.HTTP_201_CREATED)
# def create_user(email: str, password: str):
#     user = User()
#     user.email = email
#     user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode() 
#     session.add(user)
#     session.commit()
#     return {"message" : "create user"}

@app.post("/users/signup", status_code=status.HTTP_201_CREATED)
def create_user(user:User): 
    with Session(engine) as session:
        if session.exec(select(User).filter(User.email == user.email)).first():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "user is exist")

        print(1)
        user.password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode()  
        print(2)
        session.add(user)
        session.commit()
        return {"message" : "create user"}

# @app.post("/users/signin")
# def get_user(email:str, password:str):
    # with Session(engine) as session:
    #     if bcrypt.checkpw(password.encode('utf-8'), User.password('utf-8')):
    #         token = jwt.encode(token, SECRET_KEY, algorithm = ALGORITHM)
    #     return {"Authorization": token}


        # not session.exec(select(User).filter(User.email == email)).first():
        #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = "user not exist")
        # bcrypt.checkpw(password.encode('ut

# @app.get("/users/{user_id}")
# def get_user(user_id : int):
#     with Session(engine) as session:
#         user = session.exec(select(User).where(User.id == user_id)).first()
#         if not user:
#             raise HTTPException(status_code = 404, detail = "user not exist")
#         return {"result" : user}

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# def verify_password(input_password, hashed_password): #입력받은거, db에 있는거
#     return pwd_context.verify(input_password, hashed_password) 

# def get_password_hash(password): #입력받은 password
#     return pwd_context.hash(password)

# def get_user(username:str):
#     with Session(engine) as session:
#         db_user = session.exec(select(User)).all()

#         if username in db_user:
#             user_dict = db_user[username]
#             return UserInDB(**user_dict)
            
# def authenticate_user(username:str, password:str): #-> 사용자 인증하고 반환하는 함수 / 반환값은 user 아니면 False 반환
#     user = get_user(username)
#     print(3)
#     print(f"user : {user}")
#     # db에 그냥 없는경우
#     if not user: #-> get_user 함수를 통해서 username이 없으면 false 반환
#         return False
#     #db엔 있는데, 해쉬된 비밀번호가 다른경우
#     print(4)
#     if not verify_password(password, user.password): #-> 입력받은 비밀번호인 passwrod와 get_user함수에서 db에 username이 있으면 db의 hashed_password를 확인했는데 없으면 false
#         return False
#     #db에도 잇고, 해쉬된 비밀번호도 맞은경우
#     print(5)
#     print(f"user : {user}")
#     return user

# def create_access_token(data:dict):
#     to_encode = data.copy()
#     print(6)
#     print(f"data:{data}")
#     print(f"to_encode: {to_encode}")
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     print(7)
#     return encoded_jwt

# def get_current_user(token : str = Depends(oauth2_scheme)): #-> 위의 함수와 동일하게 token을 받지만 이번 함수에서는 jwt 토큰을 사용 -> 토큰을 복호화해서 검증하고 사용자 반환하기 / 아니면 http error 반환
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     ) 
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
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

# @app.post("/users/login", response_model=Token)
# def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     print(1)
#     print(form_data)
#     user = authenticate_user(form_data.username, form_data.password)
#     print(2)
#     print(user)
#     # if not user:
#     #     raise HTTPException(
#     #         status_code=status.HTTP_401_UNAUTHORIZED,
#     #         detail="incorrect username or password",
#     #         headers={"WWW-Authenticate" : "Bearer"},
#     #     )

#     access_token = create_access_token(data = {"sub":user.username})
#     print(access_token)
#     return {"access_token": access_token, "token_type":"bearer"}

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



#---------
# @app.post("/users/login", status_code=HTTP_200_OK)
# def create_access_token(user:User):
#     print(1)
#     to_encode = user.copy()
#     print(to_encode)
#     print(2)
#     with Session(engine) as session:
#         # db_user = session.exec(select(User).filter(User.password == user.password)).first()
#         if bcrypt.checkpw(user.password.encode('utf-8'), User.password.encode('utf-8')):
#             token = jwt.encode(payload = {"id":User.id}, key=SECRET_KEY, algorithm=ALGORITHM)
#         else:
#             raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "no ")
#     print(3)
#     print(token)
#     return {"Authorization" : token}

from pydantic.main import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError
from typing import Optional
# from models.models import TokenData, UserInDB, Token

#확인용도의 몫데이터
fake_users_db = {
    "johndoe": {
        "username" : "test1",
        "email" : "test1@gmail.com",
        "hashed_password" : "$2b$12$D2jH9kG2sQmCB0XXibC6/.a45dHyHMPX1unWDhswZNB5WFPSYlJmm",
        # "username": "johndoe",
        # "full_name": "John Doe",
        # "email": "johndoe@example.com",
        # "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}
# def fake_hash_password(password:str): #-> password 받아서 여기 함수에선 "fakehashed"에 입력받은 password 붙여서 출력
#     return "fakehashed" + password

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  #-> bcrypt하는것
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# class Token(BaseModel):
#     access_token :str
#     token_type : str

# class TokenData(BaseModel):
#     username: Optional[str] = None

# class User(BaseModel): # -> User정보를 불러올 테이블 만들기
#     username:str
#     email: Optional[str] = None
    # full_name: Optional[str] = None
    # disabled: Optional[bool] = None

# class UserInDB(User): #-> 해당 데이터를 pydantic 모델에 넣는다
#     hashed_password: str

def verify_password(plain_password, hashed_password): #-> password 확인하는 함수 / 전달받은 비밀번호(plain_password)와 해시되어 저장된 비밀번호(hashed_password) 확인하는것
    return pwd_context.verify(plain_password, hashed_password) #-> verify는 장고에서의 checkpw와 비슷한 용도 / True, False값으로 반환

def get_password_hash(password): #-> 사용자로 받은 비밀번호를 해시하는 함수 -> hash를 통해서
    return pwd_context.hash(password)  #-> 반환값은 해시된 비밀번호가 반환됨

def get_user(db, username : str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username:str, password:str): #-> 사용자 인증하고 반환하는 함수 / 반환값은 user 아니면 False 반환
    user = get_user(fake_db, username)
    #db에 그냥 없는경우
    if not user: #-> get_user 함수를 통해서 username이 없으면 false 반환
        return False
    #db엔 있는데, 해쉬된 비밀번호가 다른경우
    if not verify_password(password, user.hashed_password): #-> 입력받은 비밀번호인 passwrod와 get_user함수에서 db에 username이 있으면 db의 hashed_password를 확인했는데 없으면 false
        return False
    #db에도 잇고, 해쉬된 비밀번호도 맞은경우
    return user

def create_access_token(data:dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# def fake_decode_token(token): 
#     user = get_user(fake_users_db, token)
#     # return user
#     return User(
#         username=token + "fakedecoded", email="john@gmail.com", full_name="John Doe"
#     )

# def get_current_user(token: str = Depends(oauth2_scheme)): #-> 현재 유저 정보 불러오는 함수: 토큰을 입력받으면, 그 해당 토큰으로 페이크 디코드 토큰 만들어서 return
#     user = fake_decode_token(token)                        # -> 그냥 fake_decode_token 함수를 통해서만 반환할뿐
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="invaild authentication",
#             headers={"www-Authenticate" : "Bearer"}
#         )
#     return user

def get_current_user(token : str = Depends(oauth2_scheme)): #-> 위의 함수와 동일하게 token을 받지만 이번 함수에서는 jwt 토큰을 사용 -> 토큰을 복호화해서 검증하고 사용자 반환하기 / 아니면 http error 반환
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    ) 
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user:User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="inactive user")
    return current_user

# @app.post("/token")
# def login(form_data:OAuth2PasswordRequestForm = Depends()):
#     user_dict = fake_users_db.get(form_data.username) #-> fake_user_db에서 form_data로 입력받은정보중 username이 있는걸 user_dict 변수에 할당
#     if not user_dict:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="incorrect username or password")
#     user = UserInDB(**user_dict) #-> 있다면 UserInDB에있는걸 user변수에 할당
#     hashed_password = fake_hash_password(form_data.password) #-> 있다면 form_data로 입력받은 password를 fakd_hash_password 함수를 통해 hash_password 변수에 할당
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="incoreect username or password")
#     return {"access_token":user.username, "token_type": "bearer"}

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(1)
    print(form_data)

    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    print(user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="incorrect username or password",
            headers={"WWW-Authenticate" : "Bearer"},
        )
    print(3)
    access_token = create_access_token(data = {"sub":user.username})
    print(4)
    print(access_token)
    return {"access_token": access_token, "token_type":"bearer"}

# @app.get("/users/me")
# def read_users_me(current_user:str = Depends(get_current_user)):
#     return current_user


