#!/bin/bash

echo "checking if pip3 is installed..."
if which pip3; then
    echo pip3 is installed
else
    echo pip3 is not installed
    echo installing the pip3...
    sudo apt update
    sudo apt install python3-pip -y
fi

echo "checking if jsonschema module for python is installed..."
if pip3 list | grep jsonschema; then
    echo jsonschema python module is installed
else
    echo jsonschema python module is not installed
    echo installing the jsonschema python module
    sudo apt update
    pip3 install jsonschema
fi

