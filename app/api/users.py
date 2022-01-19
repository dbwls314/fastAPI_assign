from fastapi import APIRouter, status
from models.models import User, Token, UserUpdate, LoginRequest
from service.users import create_user, update_user, remove_user
from service.auth import get_access_token_after_succesful_login

router = APIRouter()

@router.post("/users/signup", status_code=status.HTTP_201_CREATED)
def post_user(user:User):
    return create_user(user=user)

@router.post("/users/login", response_model=Token, status_code=status.HTTP_200_OK)
def login_user(login_request: LoginRequest):
    return get_access_token_after_succesful_login(login_request=login_request)

@router.patch("/users/{user_id}", status_code = status.HTTP_200_OK)
def patch_user(user_id:str, user_update:UserUpdate):
    return update_user(user_id=user_id, user_update=user_update)

@router.delete("/users/{user_id}")
def delete_user(user_id:str):
    return remove_user(user_id=user_id)

