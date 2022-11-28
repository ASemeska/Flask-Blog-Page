# Baigiamasis projektas

## Installation

#### Create virtual environment in project's root directory:

```Shell
python -m venv venv
```

#### Activate the virtual environment:

- ##### For Linux / Mac:

  ```Shell
  source venv/bin/activate
  ```

- ##### For Windows:
  ```Shell
  source venv/Scripts/activate
  ```

#### Install the required packages:

```Shell
pip install -r requirements.txt
```

## Running

##### [1] Set the environment variables:

```Shell
export FLASK_APP=app
export FLASK_DEBUG=1
```

##### [2] Run the development server:
```Shell
flask run
```
or
```Shell
python app.py
```