#!/usr/bin/env python3
# ADONIS HuggingFace Model Integration

import logging
import os
import time
from typing import Dict, List, Any, Optional

class HuggingFaceModel:
    """
    HuggingFace model integration for ADONIS.
    Provides AI capabilities using HuggingFace's API and models.
    """
    
    def __init__(self, app):
        """
        Initialize the HuggingFace model.
        
        Args:
            app: Main application instance
        """
        self.app = app
        self.logger = logging.getLogger("adonis.ai.huggingface_model")
        self.config = app.config.get("ai_assistant", {})
        
        # HuggingFace settings
        self.api_key = self.config.get("huggingface_api_key", os.environ.get("HF_API_KEY", ""))
        self.model_name = self.config.get("huggingface_model_name", "google/flan-t5-large")
        self.embedding_model = self.config.get("huggingface_embedding_model", "sentence-transformers/all-MiniLM-L6-v2")
        self.max_tokens = self.config.get("max_tokens", 512)
        self.temperature = self.config.get("temperature", 0.7)
        
        # Initialize client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the HuggingFace client."""
        try:
            from huggingface_hub import HfApi, InferenceClient
            
            self.client = None
            self.pipeline = None
            
            # Check if we're using local models or API
            if self.config.get("use_huggingface_api", False):
                # Use the Inference API
                if not self.api_key:
                    self.logger.warning("HuggingFace API key not found. Some functionality may be limited.")
                
                self.client = InferenceClient(
                    model=self.model_name,
                    token=self.api_key if self.api_key else None
                )
                self.logger.info(f"HuggingFace Inference API client initialized with model {self.model_name}")
            else:
                # Use local models with transformers
                try:
                    from transformers import pipeline
                    
                    # Load model in a pipeline
                    self.logger.info(f"Loading HuggingFace model: {self.model_name}")
                    self.pipeline = pipeline(
                        "text2text-generation" if "t5" in self.model_name.lower() else "text-generation",
                        model=self.model_name,
                        device_map="auto"  # Use GPU if available
                    )
                    self.logger.info("HuggingFace pipeline initialized successfully")
                except Exception as e:
                    self.logger.error(f"Failed to initialize HuggingFace pipeline: {str(e)}")
                    self.pipeline = None
            
        except ImportError:
            self.logger.error("Failed to import huggingface_hub. Install with: pip install huggingface_hub transformers")
            self.client = None
            self.pipeline = None
    
    def generate_response(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Generate a response for a user query.
        
        Args:
            query: User's query
            context: Additional context for the query
            
        Returns:
            Generated response as a string
        """
        if self.client is None and self.pipeline is None:
            return "HuggingFace model is not initialized. Please check the logs for errors."
            
        try:
            # Build prompt based on context and query
            prompt = self._build_prompt(query, context)
            
            # Generate response
            start_time = time.time()
            
            if self.client:
                # Using Inference API
                parameters = {
                    "max_new_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "top_p": 0.95,
                    "do_sample": True,
                    "return_full_text": False
                }
                
                response = self.client.text_generation(
                    prompt,
                    **parameters
                )
                result = response[0]["generated_text"] if isinstance(response, list) else response
            
            elif self.pipeline:
                # Using local pipeline
                outputs = self.pipeline(
                    prompt,
                    max_new_tokens=self.max_tokens,
                    temperature=self.temperature,
                    top_p=0.95,
                    do_sample=True,
                    return_full_text=False
                )
                
                if isinstance(outputs, list) and outputs:
                    result = outputs[0]["generated_text"]
                else:
                    result = outputs["generated_text"] if "generated_text" in outputs else str(outputs)
                    
                # For T5 models, we get just the response without the prompt
                # For other models, check if we need to remove the prompt
                if "t5" not in self.model_name.lower() and result.startswith(prompt):
                    result = result[len(prompt):].strip()
            else:
                return "Model not available"
            
            inference_time = time.time() - start_time
            self.logger.debug(f"Generated response in {inference_time:.2f}s")
            
            # Clean up response
            if "User:" in result:
                result = result.split("User:")[0].strip()
            if "ADONIS:" in result:
                result = result.split("ADONIS:")[0].strip()
            
            return result.strip()
                
        except Exception as e:
            self.logger.error(f"Error generating response: {str(e)}")
            return f"I encountered an error while processing your request: {str(e)}"
    
    def analyze_data(self, data: Any, data_type: str) -> Dict[str, Any]:
        """
        Analyze data with the AI model.
        
        Args:
            data: The data to analyze
            data_type: Type of data (e.g., "network_scan", "packet_capture")
            
        Returns:
            Dictionary with analysis results
        """
        try:
            # Convert data to string representation
            if isinstance(data, dict):
                import json
                data_str = json.dumps(data, indent=2)
            elif isinstance(data, (list, tuple)):
                data_str = "\n".join(str(item) for item in data)
            else:
                data_str = str(data)
            
            # Truncate data if it's too large
            if len(data_str) > 4000:  # Limit for context
                data_str = data_str[:4000] + "...[truncated]"
                
            # Create prompt for analysis
            prompt = f"""
            Task: Analyze the following {data_type} data and provide insights.
            
            DATA:
            {data_str}
            
            Provide a detailed analysis including:
            1. SUMMARY: Brief overview of the data
            2. FINDINGS: Key patterns and information discovered
            3. CONCERNS: Potential security issues
            4. RECOMMENDATIONS: Suggested actions
            
            Analysis:
            """
            
            # Generate analysis
            raw_analysis = self.generate_response(prompt, {"data_type": data_type})
            
            # Process results
            sections = ["summary", "findings", "concerns", "recommendations"]
            results = {"raw_analysis": raw_analysis}
            
            # Try to extract structured information
            for section in sections:
                pattern = f"{section.upper()}:|{section.title()}:"
                if pattern in raw_analysis:
                    parts = raw_analysis.split(pattern, 1)
                    if len(parts) > 1:
                        next_section = None
                        for s in sections:
                            if s != section:
                                next_pattern = f"{s.upper()}:|{s.title()}:"
                                if next_pattern in parts[1]:
                                    next_section = parts[1].find(next_pattern)
                                    break
                        
                        if next_section:
                            results[section] = parts[1][:next_section].strip()
                        else:
                            results[section] = parts[1].strip()
            
            return results
                
        except Exception as e:
            self.logger.error(f"Error analyzing data: {str(e)}")
            return {"error": str(e)}
    
    def generate_suggestion(self, context: Dict[str, Any], task_type: str) -> List[str]:
        """
        Generate suggestions for a specific task.
        
        Args:
            context: Context information for generating suggestions
            task_type: Type of suggestion (e.g., "breakpoints", "scan_options")
            
        Returns:
            List of suggestions
        """
        try:
            # Create context string
            context_str = ""
            for key, value in context.items():
                if value and key not in ["history"]:
                    context_str += f"{key}: {value}\n"
            
            # Create prompt based on task type
            task_descriptions = {
                "breakpoints": "suitable breakpoints for debugging",
                "scan_options": "optimal network scan options",
                "filters": "useful packet capture filters",
                "commands": "helpful terminal commands"
            }
            
            task_desc = task_descriptions.get(task_type, f"suggestions for {task_type}")
            
            prompt = f"""
            Task: Based on the following context, suggest {task_desc}.
            
            CONTEXT:
            {context_str}
            
            Provide 3-5 specific suggestions with brief explanations for each.
            Format each suggestion as a numbered list item.
            
            Suggestions:
            """
            
            # Generate response
            response = self.generate_response(prompt, context)
            
            # Parse suggestions from response
            suggestions = []
            lines = response.split("\n")
            
            current_suggestion = ""
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if line.startswith(("- ", "• ", "* ", "1. ", "2. ", "3. ", "4. ", "5. ")):
                    if current_suggestion:
                        suggestions.append(current_suggestion.strip())
                    current_suggestion = line[2:] if line[1] == ' ' else line[3:]
                else:
                    if current_suggestion:
                        current_suggestion += " " + line
                        
            if current_suggestion:
                suggestions.append(current_suggestion.strip())
                
            # If no structured suggestions found, fall back to returning the whole response
            if not suggestions:
                return [response]
                
            return suggestions
                
        except Exception as e:
            self.logger.error(f"Error generating suggestions: {str(e)}")
            return [f"Error generating suggestions: {str(e)}"]
    
    def _build_prompt(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Build a prompt for the model.
        
        Args:
            query: User's query
            context: Additional context for the query
            
        Returns:
            Formatted prompt
        """
        if not context:
            context = {}
            
        # Get conversation history
        history = context.get("history", [])
        current_module = context.get("current_module", "")
        current_task = context.get("current_task", "")
        
        # Format system prompt
        system_prompt = """
        You are ADONIS AI Assistant, an intelligent assistant for the ADONIS platform.
        ADONIS is an AI-powered platform that combines advanced debugging (xdbg64), network scanning (nmap), 
        terminal access, packet analysis (Wireshark), and memory editing (Cheat Engine) in a unified interface.
        
        Your role is to assist users with these tools by providing clear, accurate, and helpful information.
        Always prioritize security and ethical use of these tools.
        """
        
        # Add context about current module and task
        if current_module:
            system_prompt += f"\nThe user is currently in the {current_module} module."
        if current_task:
            system_prompt += f"\nThe user is working on: {current_task}"
            
        # Build conversation history
        conversation = ""
        for entry in history[-5:]:  # Only include the last 5 entries for context
            role = entry.get("role", "").title()
            content = entry.get("content", "")
            conversation += f"\n{role}: {content}\n"
            
        # Assemble final prompt
        prompt = f"{system_prompt}\n\n{conversation}\nUser: {query}\n\nADONIS:"
        
        return prompt
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down HuggingFace model")
        
        # Clean up CUDA memory if using PyTorch
        if self.pipeline and hasattr(self.pipeline, "model"):
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except (ImportError, AttributeError):
                pass