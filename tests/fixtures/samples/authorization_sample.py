from fastapi import FastAPI,Depends
app = FastAPI()
def get_current_user():
    return {"id": 1}
@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)):
    return db.query(Order).filter(Order.id == order_id).first()
@app.get("/users/{user_id}/orders")
def get_user_orders(user_id: int, user=Depends(get_current_user)):
    return db.query(Order).filter(
        Order.user_id == user["id"]
    ).all()