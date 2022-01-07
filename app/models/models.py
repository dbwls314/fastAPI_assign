from typing import Optional
from sqlmodel import Field, SQLModel
from sqlalchemy import UniqueConstraint

class UserBase(SQLModel):
    id: int
    email: str
    password: str

class User(UserBase, table=True):
    __tablename__ = 'users'
    __table_args__ = (UniqueConstraint("email"),)
    id : Optional[int] = Field(default = None, primary_key=True)
    email : str = Field(regex = "[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+") 
    password : str = Field(nullable=False, max_length = 300, regex = "(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}") 

class UserResponse(UserBase):  
    id: str

class UserUpdate(SQLModel):
    id : Optional[str] = None
    email : Optional[str] = None
    password : Optional[str] = None 

class Account(SQLModel, table=True):
    __tablename__ = 'accounts'
    id : Optional[int] = Field(default = None, primary_key=True)
    price : int 
    memo : str
    user_id : int = Field(default = None, foreign_key = 'users.id')

class Trash(SQLModel, table=True):
    __talename__ = 'trashs'
    id : Optional[int] = Field(default = None, primary_key=True)
    user_id : int = Field(default = None, foreign_key = 'users.id')
    account_id : int = Field(default = None, foreign_key = 'accounts.id')
