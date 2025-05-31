"""
CLI runner for WPGuard application
"""
import sys
import asyncio
import uvicorn
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def run_server():
    """Run the FastAPI server"""
    from app.core.config import settings
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        log_level="info"
    )

def run_tests():
    """Run the test suite"""
    import pytest
    pytest.main(["-v", "tests/"])

def main():
    """Main CLI entry point"""
    if len(sys.argv) < 2:
        print("WPGuard - WordPress File Integrity Scanner")
        print("Usage:")
        print("  python run.py server    - Start the web server")
        print("  python run.py test      - Run tests")
        return
    
    command = sys.argv[1].lower()
    
    if command == "server":
        print("Starting WPGuard server...")
        run_server()
    elif command == "test":
        print("Running WPGuard tests...")
        run_tests()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: server, test")

if __name__ == "__main__":
    main()
