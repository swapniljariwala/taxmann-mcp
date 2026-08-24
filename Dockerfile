# TaxMann Research Tool — Cloud Run image
#
# Source: https://github.com/swapniljariwala/taxmann-mcp
#
# Build with Docker from the PARENT directory of this repo and the
# taxmann-scraper repo (the image embeds the TaxMann SDK package, which lives
# in the sibling repo and has no packaging metadata, so the package directory
# is copied in rather than pip-installed):
#
#     cd C:/Users/swapnil/pyapps
#     docker build -f taxmann-mcp/Dockerfile -t taxmann-mcp .
#
# The SDK is a build-time dependency of this project (private dependency repo:
# https://github.com/swapniljariwala/taxmann-scraper — see README / AGENTS.md).
# It is NOT cloned inside the Dockerfile; it must be present in the build
# context at taxmann-scraper/taxmann.

FROM python:3.12-slim

WORKDIR /app

COPY taxmann-mcp/app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY taxmann-mcp/app/main.py .
COPY taxmann-mcp/portal/ /portal/

# TaxMann SDK — imported from the sibling dependency repo (see AGENTS.md).
# Lands at /app/taxmann, importable because PYTHONPATH=/app is set below.
# (main.py's sibling-repo sys.path hack is skipped in the image — parents[2]
# does not exist there.)
COPY taxmann-scraper/taxmann ./taxmann/

ENV PYTHONPATH=/app
ENV PORT=8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
