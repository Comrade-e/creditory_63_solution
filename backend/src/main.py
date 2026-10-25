from backend.src.api_methods import app
from backend.src.db import init_db
import uvicorn

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="127.0.0.1", port=8000)