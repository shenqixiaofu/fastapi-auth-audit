from fastapi import APIRouter, Depends

from .deps import get_current_user

# 整个 router 挂鉴权，下面每个路由都受保护，不该被报
router = APIRouter(prefix="/secure", dependencies=[Depends(get_current_user)])


@router.get("")
def list_secrets():
    return []
