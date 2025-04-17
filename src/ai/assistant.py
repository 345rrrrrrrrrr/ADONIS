#!/usr/bin/env python3
# ADONIS AI Assistant

import logging
import os
import json
import time
from typing import Dict, List, Any, Optional, Callable
import threading
import queue

class AIAssistant:
    """
    AI Assistant for the ADONIS platform.
    Provides intelligent assistance for users across all modules.
    """
    
    def __init__(self, app):
        """
        Initialize the AI Assistant.
        
        Args:
            app: Main application instance
        """
        self.app = app
        self.logger = logging.getLogger("adonis.ai")
        self.config = app.config.get("ai_assistant", {})
        self.model = None
        self.enabled = self.config.get("enabled", True)
        self.privacy_mode = self.config.get("privacy_mode", True)
        self.conversation_history = []
        self.max_history = 50
        self.current_context = {}
        
        # Thread for background processing
        self.task_queue = queue.Queue()
        self.processing_thread = None
        self.running = False
        
        # Callbacks for UI notifications
        self.callbacks = {
            "on_response": None,
            "on_error": None,
            "on_status_change": None
        }
        
        # Initialize AI model
        if self.enabled:
            self._initialize_model()
            self._start_background_thread()
    
    def _initialize_model(self):
        """Initialize the AI model based on configuration."""
        model_type = self.config.get("model", "local")
        self.logger.info(f"Initializing AI model: {model_type}")
        
        try:
            if model_type == "local":
                from ai.local_model import LocalModel
                self.model = LocalModel(self.app)
            elif model_type == "openai":
                from ai.openai_model import OpenAIModel
                self.model = OpenAIModel(self.app)
            elif model_type == "huggingface":
                from ai.huggingface_model import HuggingFaceModel
                self.model = HuggingFaceModel(self.app)
            else:
                self.logger.error(f"Unknown model type: {model_type}")
                
            if self.model is not None:
                self.logger.info("AI model initialized successfully")
            
        except ImportError as e:
            self.logger.error(f"Failed to import AI model: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error initializing AI model: {str(e)}")
    
    def _start_background_thread(self):
        """Start the background processing thread."""
        self.running = True
        self.processing_thread = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name="AIAssistantThread"
        )
        self.processing_thread.start()
        self.logger.debug("AI Assistant background thread started")
    
    def _process_queue(self):
        """Process tasks from the queue in the background."""
        while self.running:
            try:
                task = self.task_queue.get(timeout=1.0)
                if task is not None:
                    task_type, args = task
                    
                    if task_type == "query":
                        query, callback = args
                        self._process_query(query, callback)
                    elif task_type == "analyze":
                        data, data_type, callback = args
                        self._process_analysis(data, data_type, callback)
                    elif task_type == "suggest":
                        context, task_type, callback = args
                        self._process_suggestion(context, task_type, callback)
                    
                    self.task_queue.task_done()
            except queue.Empty:
                # No tasks in the queue, just continue
                pass
            except Exception as e:
                self.logger.error(f"Error processing AI task: {str(e)}")
    
    def _process_query(self, query: str, callback: Callable):
        """Process a query in the background thread."""
        try:
            if self.model is None:
                raise RuntimeError("AI model not initialized")
            
            # Prepare context for the query
            context = {
                "query": query,
                "history": self.conversation_history[-10:] if self.conversation_history else [],
                "current_module": self.current_context.get("current_module"),
                "current_task": self.current_context.get("current_task")
            }
            
            # Get response from the model
            response = self.model.generate_response(query, context)
            
            # Add to conversation history
            self.conversation_history.append({
                "role": "user",
                "content": query,
                "timestamp": time.time()
            })
            self.conversation_history.append({
                "role": "assistant",
                "content": response,
                "timestamp": time.time()
            })
            
            # Trim conversation history if needed
            if len(self.conversation_history) > self.max_history:
                self.conversation_history = self.conversation_history[-self.max_history:]
            
            # Call the callback with the response
            if callback:
                callback(response)
        
        except Exception as e:
            self.logger.error(f"Error processing query: {str(e)}")
            if callback:
                callback(f"I apologize, but I encountered an error: {str(e)}")
    
    def _process_analysis(self, data: Any, data_type: str, callback: Callable):
        """Process data analysis in the background thread."""
        try:
            if self.model is None:
                raise RuntimeError("AI model not initialized")
            
            # Analyze the data using the model
            analysis = self.model.analyze_data(data, data_type)
            
            # Call the callback with the analysis results
            if callback:
                callback(analysis)
                
        except Exception as e:
            self.logger.error(f"Error analyzing data: {str(e)}")
            if callback:
                callback({"error": str(e)})
    
    def _process_suggestion(self, context: Dict[str, Any], task_type: str, callback: Callable):
        """Process suggestion generation in the background thread."""
        try:
            if self.model is None:
                raise RuntimeError("AI model not initialized")
            
            # Generate suggestions based on context and task type
            suggestions = self.model.generate_suggestion(context, task_type)
            
            # Call the callback with the suggestions
            if callback:
                callback(suggestions)
                
        except Exception as e:
            self.logger.error(f"Error generating suggestions: {str(e)}")
            if callback:
                callback([])
    
    def ask(self, query: str, callback: Optional[Callable] = None) -> None:
        """
        Ask a question to the AI assistant.
        
        Args:
            query: The user's query
            callback: Function to call with the response
        """
        if not self.enabled:
            if callback:
                callback("AI Assistant is currently disabled.")
            return
            
        self.task_queue.put(("query", (query, callback)))
    
    def analyze(self, data: Any, data_type: str, callback: Optional[Callable] = None) -> None:
        """
        Ask the AI to analyze data.
        
        Args:
            data: The data to analyze
            data_type: Type of data (e.g., "network_scan", "packet_capture", "memory_dump")
            callback: Function to call with the analysis results
        """
        if not self.enabled:
            if callback:
                callback({"error": "AI Assistant is disabled."})
            return
            
        self.task_queue.put(("analyze", (data, data_type, callback)))
    
    def suggest(self, context: Dict[str, Any], task_type: str, callback: Optional[Callable] = None) -> None:
        """
        Get suggestions for a specific task.
        
        Args:
            context: Context information for generating suggestions
            task_type: Type of suggestion (e.g., "breakpoints", "scan_options", "filters")
            callback: Function to call with the suggestions
        """
        if not self.enabled:
            if callback:
                callback([])
            return
            
        self.task_queue.put(("suggest", (context, task_type, callback)))
    
    def set_context(self, context_info: Dict[str, Any]) -> None:
        """
        Update the current context information.
        
        Args:
            context_info: Context information to update
        """
        self.current_context.update(context_info)
    
    def register_callback(self, event_type: str, callback: Callable) -> bool:
        """
        Register a callback for AI assistant events.
        
        Args:
            event_type: Type of event ("on_response", "on_error", "on_status_change")
            callback: Function to call when the event occurs
            
        Returns:
            True if registration was successful
        """
        if event_type in self.callbacks:
            self.callbacks[event_type] = callback
            return True
        return False
    
    def set_enabled(self, enabled: bool) -> None:
        """
        Enable or disable the AI assistant.
        
        Args:
            enabled: True to enable, False to disable
        """
        if self.enabled != enabled:
            self.enabled = enabled
            self.app.config.set("ai_assistant.enabled", enabled)
            self.app.config.save()
            
            if enabled and self.model is None:
                self._initialize_model()
                
            if self.callbacks["on_status_change"]:
                self.callbacks["on_status_change"](enabled)
    
    def clear_history(self) -> None:
        """Clear conversation history."""
        self.conversation_history = []
    
    def get_history(self) -> List[Dict[str, Any]]:
        """
        Get conversation history.
        
        Returns:
            List of conversation entries
        """
        return self.conversation_history.copy()
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down AI Assistant")
        self.running = False
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=2.0)
            
        # Clean up any model resources
        if self.model and hasattr(self.model, "shutdown"):
            self.model.shutdown()