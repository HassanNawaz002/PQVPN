from fastapi import FastAPI

app = FastAPI(title="PQ-VPN Control Plane")

@app.get("/")
def home():
    return {"status": "online", "message": "Post-Quantum Gateway Control Plane Ready"}

@app.get("/v1/auth/handshake")
def test_handshake():
    return {"algorithm": "ML-KEM-1024", "stage": "waiting_for_client_identity"}
