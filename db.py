import os
from sqlmodel import SQLModel, create_engine

user_name = os.environ['user_name']
user_pwd = os.environ['user_pwd']
db_host = os.environ['db_host']
db_name = os.environ['db_name']

DATABASE = f"mysql+pymysql://{user_name}:{user_pwd}@{db_host}/{db_name}?charset=utf8mb4"

engine = create_engine(
    DATABASE,
    encoding = "utf-8",
    echo = True
)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
