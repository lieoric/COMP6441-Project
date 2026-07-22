$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
conda env update --name comp6441-ctf --file environment.yml --prune
conda run --name comp6441-ctf flask --app ctf_app reset-db
