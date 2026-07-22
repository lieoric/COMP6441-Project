$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
conda run --name comp6441-ctf flask --app ctf_app reset-db
conda run --name comp6441-ctf pytest -q
