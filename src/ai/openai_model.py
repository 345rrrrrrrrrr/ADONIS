#!/usr/bin/env python3
# ADONIS OpenAI Model Integration

import logging
import os
import time
import json
from typing import Dict, List, Any, Optional

class OpenAIModel:
    """
    OpenAI model integration for ADONIS.
    Provides AI capabilities using OpenAI's API.
    """
    
    def __init__(self, app):
        """
        Initialize the OpenAI model.
        
        Args:
            app: Main application instance
        """
        self.app = app
        self.logger = logging.getLogger("adonis.ai.openai_model")
        self.config = app.config.get("ai_assistant", {})
        
        # OpenAI settings
        self.api_key = self.config.get("openai_api_key", os.environ.get("OPENAI_API_KEY", ""))
        self.model_name = self.config.get("openai_model_name", "gpt-3.5-turbo")
        self.embedding_model = self.config.get("openai_embedding_model", "text-embedding-ada-002")
        self.max_tokens = self.config.get("max_tokens", 1024)
        self.temperature = self.config.get("temperature", 0.7)
        
        # Initialize client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the OpenAI client."""
        try:
            import openai
            
            if not self.api_key:
                self.logger.error("OpenAI API key not found. Set it in the configuration or OPENAI_API_KEY environment variable.")
                return
            
            # Set API key
            openai.api_key = self.api_key
            
            self.client = openai
            self.logger.info(f"OpenAI client initialized with model {self.model_name}")
            
        except ImportError:
            self.logger.error("Failed to import openai. Install with: pip install openai")
            self.client = None
    
    def generate_response(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Generate a response for a user query.
        
        Args:
            query: User's query
            context: Additional context for the query
            
        Returns:
            Generated response as a string
        """
        if self.client is None:
            return "OpenAI model is not initialized. Please check the logs for errors."
            
        try:
            # Build messages based on context and query
            messages = self._build_messages(query, context)
            
            # Make API call
            start_time = time.time()
            response = self.client.ChatCompletion.create(
                model=self.model_name,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                top_p=0.95,
                n=1,
                stream=False
            )
            inference_time = time.time() - start_time
            
            self.logger.debug(f"Generated response in {inference_time:.2f}s")
            
            # Extract and return response text
            if response and response.choices and len(response.choices) > 0:
                return response.choices[0].message["content"].strip()
            else:
                return "No response generated."
                
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
            if len(data_str) > 8000:  # OpenAI has token limits
                data_str = data_str[:8000] + "...[truncated]"
                
            # Format prompt for structured analysis
            messages = [
                {"role": "system", "content": "You are ADONIS AI Assistant, analyzing data for cybersecurity purposes. Provide detailed, structured analysis."},
                {"role": "user", "content": f"""
                Analyze the following {data_type} data and provide insights.
                
                DATA:
                {data_str}
                
                Format your response with the following sections:
                - SUMMARY: Brief overview of what the data shows
                - FINDINGS: Key information and patterns discovered
                - CONCERNS: Potential security issues or vulnerabilities
                - RECOMMENDATIONS: Suggested actions based on this data
                """}
            ]
            
            # Generate analysis
            start_time = time.time()
            response = self.client.ChatCompletion.create(
                model=self.model_name,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=0.5,  # Lower temperature for more factual analysis
                top_p=0.95,
                n=1,
                stream=False
            )
            inference_time = time.time() - start_time
            
            self.logger.debug(f"Generated analysis in {inference_time:.2f}s")
            
            # Extract raw analysis
            raw_analysis = response.choices[0].message["content"].strip()
            
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
            
            # Format prompt based on task type
            task_descriptions = {
                "breakpoints": "suitable breakpoints for debugging",
                "scan_options": "optimal network scan options",
                "filters": "useful packet capture filters",
                "commands": "helpful terminal commands"
            }
            
            task_desc = task_descriptions.get(task_type, f"suggestions for {task_type}")
            
            messages = [
                {"role": "system", "content": f"You are ADONIS AI Assistant, providing expert suggestions for {task_desc}."},
                {"role": "user", "content": f"""
                Based on the following context, suggest {task_desc}:
                
                CONTEXT:
                {context_str}
                
                Provide 3-5 specific suggestions with brief explanations for each.
                Format each suggestion as a numbered list item.
                """}
            ]
            
            # Generate suggestions
            response = self.client.ChatCompletion.create(
                model=self.model_name,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=0.7,
                top_p=0.95,
                n=1,
                stream=False
            )
            
            # Extract and parse suggestions
            raw_suggestions = response.choices[0].message["content"].strip()
            
            # Parse suggestions from response
            suggestions = []
            lines = raw_suggestions.split("\n")
            
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
                return [raw_suggestions]
                
            return suggestions
                
        except Exception as e:
            self.logger.error(f"Error generating suggestions: {str(e)}")
            return [f"Error generating suggestions: {str(e)}"]
    
    def _build_messages(self, query: str, context: Dict[str, Any] = None) -> List[Dict[str, str]]:
        """
        Build messages for the OpenAI API.
        
        Args:
            query: User's query
            context: Additional context for the query
            
        Returns:
            List of message dictionaries
        """
        if not context:
            context = {}
            
        # Get conversation history
        history = context.get("history", [])
        current_module = context.get("current_module", "")
        current_task = context.get("current_task", "")
        
        # Create system message
        system_content = """
        You are ADONIS AI Assistant, an intelligent assistant for the ADONIS platform.
        ADONIS is an AI-powered platform that combines advanced debugging (xdbg64), network scanning (nmap), 
        terminal access, packet analysis (Wireshark), and memory editing (Cheat Engine) in a unified interface.
        
        Your role is to assist users with these tools by providing clear, accurate, and helpful information.
        Always prioritize security and ethical use of these tools.
        """
        
        # Add context about current module and task
        if current_module:
            system_content += f"\nThe user is currently in the {current_module} module."
        if current_task:
            system_content += f"\nThe user is working on: {current_task}"
            
        messages = [
            {"role": "system", "content": system_content}
        ]
        
        # Add conversation history
        for entry in history[-5:]:  # Only include the last 5 entries for context
            role = entry.get("role", "")
            if role not in ["system", "user", "assistant"]:
                role = "user" if role == "human" else "assistant"
                
            content = entry.get("content", "")
            if content:
                messages.append({"role": role, "content": content})
                
        # Add current query
        messages.append({"role": "user", "content": query})
        
        return messages
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down OpenAI model")
        # No specific cleanup needed for the OpenAI client