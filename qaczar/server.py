# Description: Server for qaczar

import fastapi
import uvicorn
import qaczar


app = fastapi.FastAPI()

@app.get("/canvas/{canvas}")
def get_canvas(canvas: str):
    if not canvas.endswith(".canvas"):
        canvas += ".canvas"
    # The idea is that final output of the canvas is returned
    # If it is already up to date, nothing is done
    # If it is out of date, the entire workflow is executed
    filenames = qaczar.execute_canvas(canvas)
    if len(filenames) == 1:
        return fastapi.responses.FileResponse(filenames[0])
    else:
        return filenames
    

# Return static files
@app.get("/file/{filename}")
def get_static(filename: str):
    return fastapi.responses.FileResponse(filename)

    
@app.get("/canvas")
def get_canvases():
    return qaczar.list_canvas_files()


def start_local_server():
    uvicorn.run(app, host="localhost", port=8000)

