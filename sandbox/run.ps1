# Aegis sandbox launcher (Windows / Docker Desktop).
#   .\run.ps1              # sandbox the current directory
#   .\run.ps1 C:\path\repo # sandbox a specific repo
# Only the repo is mounted; no network; no privileges. Aegis runs inside.
param([string]$Repo = (Get-Location).Path)

$ErrorActionPreference = "Stop"
docker build -t aegis-sandbox $PSScriptRoot

docker run --rm -it `
  -v "${Repo}:/work" `
  --network none `
  --cap-drop ALL `
  --security-opt no-new-privileges `
  aegis-sandbox
