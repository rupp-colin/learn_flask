#!/bin/bash

export FLASK_APP=$1
export FLASK_ENV=$2

flask init-db && flask run
