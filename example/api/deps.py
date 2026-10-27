from fastapi import Depends, HTTPException


def get_db():
    yield None


def get_current_user(token: str = ""):
    if not token:
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"id": 1}
