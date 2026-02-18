"""
Main entry point for the test samples service.
"""

import uvicorn


def main():
    """Run the FastAPI application."""
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8081,
        reload=True,
    )


if __name__ == "__main__":
    main()
