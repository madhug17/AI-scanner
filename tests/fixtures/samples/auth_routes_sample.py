from fastapi import FastAPI,HTTPException,Depends
app = FastAPI()
def get_current_user():
    return {"user": "test"}
@app.get("/public-data")
def get_public_data():
    return {"data": "example"}
@app.get("/profile")
def get_profile(user=Depends(get_current_user)):
    return {"user": user}
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    return {"deleted": user_id}