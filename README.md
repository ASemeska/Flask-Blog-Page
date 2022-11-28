Baigiamasis projektas
Installation
Create virtual environment in project's root directory:
python -m venv venv
Activate the virtual environment:
For Linux / Mac:
source venv/bin/activate
For Windows:
source venv/Scripts/activate
Install the required packages:
pip install -r requirements.txt
Running
[1] Set the environment variables:
export FLASK_APP=app
export FLASK_DEBUG=1
[2] Run the development server:
python app.py 
or
flask run