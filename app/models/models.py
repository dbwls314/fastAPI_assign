from typing import Optional
from pydantic.main import BaseModel
from sqlmodel import Field, SQLModel

from sqlalchemy import UniqueConstraint

class UserBase(SQLModel):
    id: int
    username: str
    email: str
    password: str

class User(UserBase, table=True):
    __tablename__ = 'users'
    __table_args__ = (UniqueConstraint("email"),)
    id : Optional[int] = Field(default = None, primary_key=True)
    username : str = Field(max_length=25)
    email : str = Field(regex = "[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+") 
    password : str = Field(nullable=False, max_length = 300, regex = "(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}") 

#     class Config:
#         orm_mode=True

class UserResponse(UserBase):  
    id: str

class UserUpdate(SQLModel):
    id : Optional[str] = None
    username : Optional[str] = None
    email : Optional[str] = None
    password : Optional[str] = None


#--

class Token(BaseModel):
    access_token :str
    token_type : str

class TokenData(BaseModel):
    username: Optional[str] = None

# class User(BaseModel): # -> User정보를 불러올 테이블 만들기
#     username:str
#     email: Optional[str] = None
#     full_name: Optional[str] = None
#     disabled: Optional[bool] = None

class UserInDB(User): #-> 해당 데이터를 pydantic 모델에 넣는다
    hashed_password: str
#--

class Account(SQLModel, table=True):
    __tablename__ = 'accounts'
    id : Optional[int] = Field(default = None, primary_key=True)
    price : int 
    memo : str
    user_id : int = Field(default = None, foreign_key = 'users.id')

class Trash(SQLModel, table=True):
    __talename__ = 'trashes'
    id : Optional[int] = Field(default = None, primary_key=True)
    user_id : int = Field(default = None, foreign_key = 'users.id')
    account_id : int = Field(default = None, foreign_key = 'accounts.id')
