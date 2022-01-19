from fastapi import Depends
from sqlmodel import Session
from models.models import Account, AccountUpdate
from service.auth import get_current_user
from db import engine
from typing import Dict

session = Session(bind = engine)

def create_account(account:Account, token:str = Depends(get_current_user)) -> Dict:
    account.memo = account.memo
    account.price = account.price
    account.user_id = token.id

    session.add(account)
    session.commit()
    return {"message" : "create account"}    

def update_account(account:AccountUpdate, token:str = Depends(get_current_user)) -> Dict:
    user_accounts = session.query(Account).filter(Account.user_id == token.id)
    

    for user_account in user_accounts: 
        if user_account.id == account.id:
            user_account.memo = account.memo
            user_account.price = account.price
        
    session.add(user_account)
    session.commit()
    session.refresh(user_account)
    return {"message" : "update account"}

