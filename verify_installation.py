#!/usr/bin/env python3
"""
Verification script to check that all dependencies are properly installed
and the FastAPI application can be imported and started.
"""

import sys
import subprocess

def check_imports():
    """Check that all core dependencies can be imported"""
    try:
        print("🔍 Checking core imports...")
        
        # FastAPI core
        import fastapi
        import uvicorn
        import pydantic
        print(f"✅ FastAPI {fastapi.__version__}")
        print(f"✅ Uvicorn {uvicorn.__version__}")
        print(f"✅ Pydantic {pydantic.__version__}")
        
        # HTTP clients
        import httpx
        import requests
        print(f"✅ HTTPX {httpx.__version__}")
        print(f"✅ Requests {requests.__version__}")
        
        # Job processing
        import celery
        import redis
        print(f"✅ Celery {celery.__version__}")
        print(f"✅ Redis {redis.__version__}")
        
        # WebSocket
        import websockets
        print(f"✅ WebSockets {websockets.__version__}")
        
        # Utilities
        import validators
        import cachetools
        import jwt
        print(f"✅ Validators {validators.__version__}")
        print(f"✅ CacheTools {cachetools.__version__}")
        print(f"✅ PyJWT {jwt.__version__}")
        
        print("\n🎉 All core dependencies imported successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def check_application():
    """Check that our FastAPI application can be imported"""
    try:
        print("\n🔍 Checking FastAPI application...")
        from src.api.main import app
        from src.api.models import AnalysisRequest, AnalysisResponse
        from src.api.utils.validators import GitHubURLValidator
        from src.api.utils.exceptions import CaponierException
        
        print("✅ FastAPI application imports successfully")
        print("✅ Pydantic models import successfully") 
        print("✅ URL validators import successfully")
        print("✅ Custom exceptions import successfully")
        
        # Test URL validation
        test_url = "https://github.com/microsoft/vscode"
        normalized = GitHubURLValidator.normalize_github_url(test_url)
        print(f"✅ URL validation works: {test_url} -> {normalized}")
        
        print("\n🎉 FastAPI application is ready!")
        return True
        
    except Exception as e:
        print(f"❌ Application error: {e}")
        return False

def main():
    """Main verification function"""
    print("🚀 Caponier MVP - Dependency Verification")
    print("=" * 50)
    
    success = True
    
    # Check Python version
    print(f"🐍 Python version: {sys.version}")
    if sys.version_info < (3, 11):
        print("⚠️  Warning: Python 3.11+ recommended")
    
    # Check imports
    if not check_imports():
        success = False
    
    # Check application
    if not check_application():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All checks passed! Ready to proceed with development.")
        print("\n📝 Next steps:")
        print("   1. Start development server: python3 -m uvicorn src.api.main:app --reload")
        print("   2. Visit API docs: http://localhost:8000/docs")
        print("   3. Test health endpoint: curl http://localhost:8000/health")
        return 0
    else:
        print("❌ Some checks failed. Please resolve the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
