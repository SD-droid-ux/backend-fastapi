#!/bin/bash
# Script para iniciar o FastAPI com Uvicorn
uvicorn backend.main:app --host=0.0.0.0 --port=8000
