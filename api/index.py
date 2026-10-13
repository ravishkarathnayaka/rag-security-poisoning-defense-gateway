"""Vercel Serverless Function entry point for RAG Security Gateway API."""

import os
import sys

# Ensure root directory is in Python path for Vercel serverless environment
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from api.app import create_app  # noqa: E402

# Vercel ASGI application handler
app = create_app()
