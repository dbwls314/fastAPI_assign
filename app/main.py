from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from db import create_db_and_tables
from api import users, account

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    create_db_and_tables()

app.include_router(users.router)
app.include_router(account.router)

