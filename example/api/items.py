from fastapi import APIRouter, Depends

from .deps import get_current_user, get_db

router = APIRouter(prefix="/items")


@router.get("")
def list_items(db=Depends(get_db)):
    # 漏了鉴权，会被报出来
    return []


@router.post("")
def create_item(name: str, user=Depends(get_current_user), db=Depends(get_db)):
    # 有鉴权，不会被报
    return {"name": name}
