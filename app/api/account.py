from fastapi import APIRouter, status, Depends
from models.models import Account, AccountUpdate
from service.auth import get_current_user
from service.account import create_account, update_account

router = APIRouter()

@router.post('/accounts', status_code=status.HTTP_201_CREATED)
def post_account(account:Account, token : str = Depends(get_current_user)):
    return create_account(account=account, token=token) 

@router.patch('/accounts/{account_id}', status_code=status.HTTP_200_OK)
def post_account(account:Account, token : dict = Depends(get_current_user)):
    return create_account(account=account, token=token)   

