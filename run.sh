#!/bin/bash

python3 get_results.py

python3 mitre_eval.py

python3 host.py $1