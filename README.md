# Online_voting

## Working with the repo

Make sure you make changes on your branch and then create pull requests
Run,

`
git checkout -b mihir
`

Also, stay updated with the master before making any changes

## Installation

To set up the flask environment, first create a virtual environment `env`

```
cd online_voting
pip3 install virtualenv
virtualenv env
. env/bin/activate
```

Above commands will activate a virtual environment. 
Now, install all the dependencies,

```
pip3 install -r requirements.txt
```

## Running the server

```
./run.sh
```

You have to set environment variables and run python manually if on windows
