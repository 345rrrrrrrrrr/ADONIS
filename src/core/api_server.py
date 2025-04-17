#!/usr/bin/env python3
# ADONIS API Server

import os
import logging
import threading
import time
import json
from typing import Dict, List, Any, Optional, Callable
from fastapi import FastAPI, Depends, HTTPException, Security, status

class APIServer:
    """
    RESTful API server for ADONIS.
    Provides external access to ADONIS functionality.
    """
    
    def __init__(self, app):
        """
        Initialize the API server.
        
        Args:
            app: Main application instance
        """
        self.app = app
        self.logger = logging.getLogger("adonis.core.api_server")
        self.config = app.config.get("api", {})
        self.running = False
        self.server = None
        self.thread = None
        self.routes = {}
    
    def start(self) -> bool:
        """
        Start the API server.
        
        Returns:
            True if the server was started successfully
        """
        if self.running:
            self.logger.warning("API server is already running")
            return True
            
        # Check if API is enabled
        if not self.config.get("enabled", False):
            self.logger.info("API server is disabled in configuration")
            return True  # Not an error, just disabled
        
        try:
            # Import FastAPI components
            try:
                from fastapi import FastAPI, Depends, HTTPException, Security, status
                from fastapi.security import APIKeyHeader
                from fastapi.middleware.cors import CORSMiddleware
                import uvicorn
            except ImportError:
                self.logger.error("Failed to import FastAPI. Please install required dependencies.")
                self.logger.error("Run: pip install fastapi uvicorn[standard]")
                return False
                
            # Create FastAPI app
            api_app = FastAPI(
                title="ADONIS API",
                description="ADONIS REST API for external integration",
                version="1.0.0"
            )
            
            # Set up CORS
            origins = self.config.get("cors_origins", ["http://localhost:8000"])
            api_app.add_middleware(
                CORSMiddleware,
                allow_origins=origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
            # Set up authentication if required
            if self.config.get("require_auth", True):
                api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
                
                async def get_api_key(api_key: str = Security(api_key_header)):
                    if api_key is None:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="API Key required"
                        )
                    
                    # Validate API key
                    if not self._validate_api_key(api_key):
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid API Key"
                        )
                    
                    return api_key
                
                # Dependency for protected routes
                self.auth_dependency = Depends(get_api_key)
            else:
                # No auth required
                self.auth_dependency = None
            
            # Register routes
            self._register_routes(api_app)
            
            # Start the server in a separate thread
            host = self.config.get("host", "127.0.0.1")
            port = self.config.get("port", 8000)
            
            def run_server():
                uvicorn.run(
                    api_app,
                    host=host,
                    port=port,
                    log_level="error",
                    access_log=False
                )
            
            self.thread = threading.Thread(
                target=run_server,
                daemon=True,
                name="APIServerThread"
            )
            self.thread.start()
            
            self.running = True
            self.logger.info(f"API server started on {host}:{port}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start API server: {str(e)}")
            return False
    
    def stop(self) -> None:
        """Stop the API server."""
        if not self.running:
            return
            
        self.logger.info("Stopping API server...")
        self.running = False
        
        # The uvicorn server will be terminated when the main process exits
        # since the thread is a daemon thread
    
    def _register_routes(self, app):
        """
        Register API routes.
        
        Args:
            app: FastAPI application instance
        """
        from fastapi import Body, Path, Query, Request
        
        @app.get("/api/status")
        def get_status():
            """Get the status of the ADONIS platform."""
            return {
                "status": "running",
                "version": self.app.config.get("system.version", "0.1.0"),
                "modules": [
                    {
                        "name": name,
                        "status": module.get_status().get("status", "unknown")
                    }
                    for name, module in self.app.module_manager.get_all_modules().items()
                ]
            }
        
        @app.get("/api/modules")
        def get_modules(auth: str = self.auth_dependency):
            """Get information about available modules."""
            return {
                "modules": [
                    {
                        "name": name,
                        "status": module.get_status()
                    }
                    for name, module in self.app.module_manager.get_all_modules().items()
                ]
            }
        
        @app.get("/api/modules/{module_name}")
        def get_module(module_name: str = Path(...), auth: str = self.auth_dependency):
            """Get information about a specific module."""
            module = self.app.module_manager.get_module(module_name)
            if not module:
                raise HTTPException(status_code=404, detail=f"Module {module_name} not found")
                
            return {
                "name": module_name,
                "status": module.get_status()
            }
        
        # Register module-specific API routes
        for name, module in self.app.module_manager.get_all_modules().items():
            if hasattr(module, "register_api_routes"):
                module.register_api_routes(app, self.auth_dependency)
    
    def _validate_api_key(self, api_key: str) -> bool:
        """
        Validate an API key.
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if the API key is valid
        """
        # Get valid API keys from configuration
        valid_keys = self.config.get("api_keys", [])
        
        # Check if key is in valid keys
        if api_key in valid_keys:
            return True
            
        # If user manager is initialized, check user API keys
        if hasattr(self.app, "user_manager"):
            for username, user in self.app.user_manager.users.items():
                if hasattr(user, "api_keys") and api_key in user.api_keys.values():
                    return True
        
        return False
    
    def register_route(self, route_path: str, handler: Callable, methods: List[str] = None) -> bool:
        """
        Register a custom API route.
        
        Args:
            route_path: URL path for the route
            handler: Function to handle the route
            methods: HTTP methods to support (default: ["GET"])
            
        Returns:
            True if the route was registered successfully
        """
        if not methods:
            methods = ["GET"]
            
        self.routes[route_path] = {
            "handler": handler,
            "methods": methods
        }
        
        self.logger.debug(f"Registered API route: {route_path} ({', '.join(methods)})")
        
        return True