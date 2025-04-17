#!/usr/bin/env python3
# ADONIS Local AI Model

import logging
import os
import time
from typing import Dict, List, Any, Optional

class LocalModel:
    """
    Local AI model implementation for ADONIS.
    Uses offline transformer models for AI capabilities.
    """
    
    def __init__(self, app):
        """
        Initialize the local model.
        
        Args:
            app: Main application instance
        """
        self.app = app
        self.logger = logging.getLogger("adonis.ai.local_model")
        self.config = app.config.get("ai_assistant", {})
        
        # Model settings
        self.model_dir = os.path.expanduser(
            self.config.get("model_dir", "~/.adonis/models")
        )
        self.model_name = self.config.get("local_model_name", "ggml-model")
        self.model_type = self.config.get("local_model_type", "llama")
        self.embedding_model_name = self.config.get("embedding_model", "all-MiniLM-L6-v2")
        
        # Model instances
        self.llm = None
        self.embedding_model = None
        
        # Create model directory if it doesn't exist
        if not os.path.exists(self.model_dir):
            try:
                os.makedirs(self.model_dir, mode=0o700, exist_ok=True)
                self.logger.info(f"Created model directory: {self.model_dir}")
            except Exception as e:
                self.logger.error(f"Failed to create model directory: {str(e)}")
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self) -> None:
        """Initialize the language and embedding models."""
        try:
            self.logger.info("Initializing local AI models")
            
            # Check if we should use GPU
            use_gpu = self.config.get("use_gpu", False)
            
            # Path to model file
            model_path = os.path.join(self.model_dir, f"{self.model_name}")
            if not os.path.exists(model_path) and not os.path.exists(f"{model_path}.bin"):
                self.logger.warning(f"Model file not found: {model_path}")
                self._download_default_model()
            
            # Initialize language model based on model type
            if self.model_type.lower() in ["llama", "llama2"]:
                self._init_llama_model(model_path, use_gpu)
            elif self.model_type.lower() in ["mpt", "mpt-7b"]:
                self._init_mpt_model(model_path, use_gpu)
            elif self.model_type.lower() == "gpt-j":
                self._init_gptj_model(model_path, use_gpu)
            elif self.model_type.lower() == "gpt-2":
                self._init_gpt2_model(model_path, use_gpu)
            else:
                self._init_transformer_model(model_path, use_gpu)
            
            # Initialize embedding model
            self._init_embedding_model(use_gpu)
            
            self.logger.info("Local AI models initialized successfully")
            
        except ImportError as e:
            self.logger.error(f"Failed to import required libraries: {str(e)}")
            self.logger.error("Please install the required dependencies for AI functionality")
        except Exception as e:
            self.logger.error(f"Error initializing models: {str(e)}")
    
    def _init_llama_model(self, model_path: str, use_gpu: bool) -> None:
        """
        Initialize a LLaMA model.
        
        Args:
            model_path: Path to the model file
            use_gpu: Whether to use GPU acceleration
        """
        try:
            from llama_cpp import Llama
            
            # Check if path exists with .bin extension
            if os.path.exists(f"{model_path}.bin"):
                model_path = f"{model_path}.bin"
            
            self.logger.info(f"Loading LLaMA model from {model_path}")
            
            # Configure model parameters
            context_window = self.config.get("context_window", 2048)
            n_gpu_layers = -1 if use_gpu else 0  # -1 means all layers on GPU if possible
            
            self.llm = Llama(
                model_path=model_path,
                n_ctx=context_window,
                n_gpu_layers=n_gpu_layers,
                verbose=False
            )
            
            self.logger.info("LLaMA model loaded successfully")
            
        except ImportError:
            self.logger.error("Could not import llama_cpp. Install with: pip install llama-cpp-python")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load LLaMA model: {str(e)}")
            raise
    
    def _init_mpt_model(self, model_path: str, use_gpu: bool) -> None:
        """
        Initialize an MPT model.
        
        Args:
            model_path: Path to the model file
            use_gpu: Whether to use GPU acceleration
        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
            self.logger.info(f"Loading MPT model from {model_path} on {device}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.llm = AutoModelForCausalLM.from_pretrained(
                model_path,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                trust_remote_code=True,
                device_map=device
            )
            
            self.logger.info("MPT model loaded successfully")
            
        except ImportError:
            self.logger.error("Could not import required libraries. Install transformers and torch.")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load MPT model: {str(e)}")
            raise
    
    def _init_gptj_model(self, model_path: str, use_gpu: bool) -> None:
        """
        Initialize a GPT-J model.
        
        Args:
            model_path: Path to the model file
            use_gpu: Whether to use GPU acceleration
        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
            self.logger.info(f"Loading GPT-J model from {model_path} on {device}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.llm = AutoModelForCausalLM.from_pretrained(
                model_path,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                device_map=device
            )
            
            self.logger.info("GPT-J model loaded successfully")
            
        except ImportError:
            self.logger.error("Could not import required libraries. Install transformers and torch.")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load GPT-J model: {str(e)}")
            raise
    
    def _init_gpt2_model(self, model_path: str, use_gpu: bool) -> None:
        """
        Initialize a GPT-2 model.
        
        Args:
            model_path: Path to the model file
            use_gpu: Whether to use GPU acceleration
        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
            self.logger.info(f"Loading GPT-2 model from {model_path} on {device}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.llm = AutoModelForCausalLM.from_pretrained(
                model_path,
                device_map=device
            )
            
            self.logger.info("GPT-2 model loaded successfully")
            
        except ImportError:
            self.logger.error("Could not import required libraries. Install transformers and torch.")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load GPT-2 model: {str(e)}")
            raise
    
    def _init_transformer_model(self, model_path: str, use_gpu: bool) -> None:
        """
        Initialize a generic transformer model using Hugging Face pipeline.
        
        Args:
            model_path: Path to the model file
            use_gpu: Whether to use GPU acceleration
        """
        try:
            from transformers import pipeline
            
            device = 0 if use_gpu and self._is_gpu_available() else -1  # -1 means CPU
            self.logger.info(f"Loading transformer model from {model_path} on {'GPU' if device >= 0 else 'CPU'}")
            
            self.llm = pipeline(
                "text-generation",
                model=model_path,
                device=device
            )
            
            self.logger.info("Transformer model loaded successfully")
            
        except ImportError:
            self.logger.error("Could not import transformers. Install with: pip install transformers")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load transformer model: {str(e)}")
            raise
    
    def _init_embedding_model(self, use_gpu: bool) -> None:
        """
        Initialize the sentence embedding model.
        
        Args:
            use_gpu: Whether to use GPU acceleration
        """
        try:
            from sentence_transformers import SentenceTransformer
            
            # Check if model exists in the model directory
            embedding_model_path = os.path.join(self.model_dir, self.embedding_model_name)
            if os.path.exists(embedding_model_path):
                model_name_or_path = embedding_model_path
            else:
                model_name_or_path = self.embedding_model_name
            
            self.logger.info(f"Loading embedding model: {model_name_or_path}")
            
            device = "cuda" if use_gpu and self._is_gpu_available() else "cpu"
            self.embedding_model = SentenceTransformer(model_name_or_path, device=device)
            
            self.logger.info("Embedding model loaded successfully")
            
        except ImportError:
            self.logger.error("Could not import sentence_transformers. Install with: pip install sentence-transformers")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load embedding model: {str(e)}")
            # Not raising here as embedding model is optional
            
    def _is_gpu_available(self) -> bool:
        """
        Check if GPU is available for model inference.
        
        Returns:
            True if GPU is available
        """
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            return False
        except Exception:
            return False
    
    def _download_default_model(self) -> None:
        """Download a default small model for initial use."""
        try:
            self.logger.info("Downloading default model. This may take some time...")
            
            # Determine which model to download based on model type
            model_id = "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF"
            filename = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
            
            import huggingface_hub
            
            # Create model directory if needed
            os.makedirs(self.model_dir, exist_ok=True)
            
            # Download the model
            huggingface_hub.hf_hub_download(
                repo_id=model_id,
                filename=filename,
                local_dir=self.model_dir
            )
            
            # Update model name
            self.model_name = filename
            self.model_type = "llama"
            
            # Save to config
            self.app.config.set("ai_assistant.local_model_name", filename)
            self.app.config.set("ai_assistant.local_model_type", "llama")
            self.app.config.save()
            
            self.logger.info(f"Default model downloaded to {self.model_dir}/{filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to download default model: {str(e)}")
    
    def generate_response(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Generate a response for a user query.
        
        Args:
            query: User's query
            context: Additional context for the query
            
        Returns:
            Generated response as a string
        """
        if self.llm is None:
            return "AI model is not initialized. Please check the logs for errors."
            
        try:
            # Build prompt based on context and query
            prompt = self._build_prompt(query, context)
            
            # Different models have different inference methods
            if isinstance(self.llm, str):
                # This is a placeholder for when model initialization failed
                return "AI model is not properly initialized. Please check the logs for errors."
                
            if hasattr(self.llm, "create_completion"):  # LLaMA-cpp model
                start_time = time.time()
                response = self.llm.create_completion(
                    prompt, 
                    max_tokens=512,
                    temperature=0.7,
                    top_p=0.95,
                    stop=["User:", "ADONIS:"]
                )
                inference_time = time.time() - start_time
                
                self.logger.debug(f"Generated response in {inference_time:.2f}s")
                return response["choices"][0]["text"].strip()
                
            elif hasattr(self.llm, "generate") and hasattr(self, "tokenizer"):  # HF Transformer model
                inputs = self.tokenizer(prompt, return_tensors="pt")
                if next(self.llm.parameters()).is_cuda:
                    inputs = {k: v.cuda() for k, v in inputs.items()}
                    
                start_time = time.time()
                outputs = self.llm.generate(
                    **inputs,
                    max_new_tokens=512,
                    temperature=0.7,
                    top_p=0.95,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
                inference_time = time.time() - start_time
                
                response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
                response = response[len(prompt):].strip()  # Remove the prompt
                
                # Clean up response
                if "User:" in response:
                    response = response.split("User:")[0].strip()
                if "ADONIS:" in response:
                    response = response.split("ADONIS:")[0].strip()
                    
                self.logger.debug(f"Generated response in {inference_time:.2f}s")
                return response
                
            elif hasattr(self.llm, "__call__"):  # HF pipeline
                start_time = time.time()
                result = self.llm(
                    prompt,
                    max_new_tokens=512,
                    temperature=0.7,
                    top_p=0.95,
                    do_sample=True
                )
                inference_time = time.time() - start_time
                
                response = result[0]["generated_text"][len(prompt):].strip()
                
                # Clean up response
                if "User:" in response:
                    response = response.split("User:")[0].strip()
                if "ADONIS:" in response:
                    response = response.split("ADONIS:")[0].strip()
                    
                self.logger.debug(f"Generated response in {inference_time:.2f}s")
                return response
                
            else:
                return "Unsupported model type or model not initialized properly."
                
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
            # Convert data to string representation for LLM processing
            if isinstance(data, dict):
                import json
                data_str = json.dumps(data, indent=2)
            elif isinstance(data, (list, tuple)):
                data_str = "\n".join(str(item) for item in data)
            else:
                data_str = str(data)
                
            # Create prompt for analysis
            prompt = f"""
            ADONIS AI Assistant: Analyze the following {data_type} data and provide insights.
            
            DATA:
            {data_str[:10000]}  # Limit data size
            
            Provide a detailed analysis including:
            1. Summary of the data
            2. Key findings
            3. Potential security concerns
            4. Recommended actions
            
            ANALYSIS:
            """
            
            # Use the model to analyze
            response = self.generate_response(prompt, {"data_type": data_type})
            
            # Process results
            sections = ["summary", "findings", "concerns", "recommendations"]
            results = {"raw_analysis": response}
            
            # Try to extract structured information (this is a simple approach)
            for section in sections:
                pattern = f"{section.upper()}:|{section.title()}:"
                if pattern in response:
                    parts = response.split(pattern, 1)
                    if len(parts) > 1:
                        next_section = None
                        for s in sections:
                            if s != section:
                                if f"{s.upper()}:" in parts[1] or f"{s.title()}:" in parts[1]:
                                    next_section = parts[1].find(f"{s.upper()}:")
                                    if next_section == -1:
                                        next_section = parts[1].find(f"{s.title()}:")
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
            context_str = "\n".join([f"{k}: {v}" for k, v in context.items() if v])
            
            # Create prompt based on task type
            prompts = {
                "breakpoints": f"""
                ADONIS AI Assistant: Based on the following context, suggest suitable breakpoints for debugging:
                
                CONTEXT:
                {context_str}
                
                Suggest 3-5 specific breakpoints with brief explanations for each:
                """,
                
                "scan_options": f"""
                ADONIS AI Assistant: Based on the following context, suggest optimal network scan options:
                
                CONTEXT:
                {context_str}
                
                Suggest 3-5 scan configurations with justifications:
                """,
                
                "filters": f"""
                ADONIS AI Assistant: Based on the following context, suggest useful packet capture filters:
                
                CONTEXT:
                {context_str}
                
                Suggest 3-5 specific capture filters with explanations:
                """,
                
                "commands": f"""
                ADONIS AI Assistant: Based on the following context, suggest helpful terminal commands:
                
                CONTEXT:
                {context_str}
                
                Suggest 3-5 useful commands with explanations:
                """
            }
            
            if task_type not in prompts:
                prompt = f"""
                ADONIS AI Assistant: Based on the following context, provide suggestions for {task_type}:
                
                CONTEXT:
                {context_str}
                
                Provide 3-5 specific suggestions with brief explanations:
                """
            else:
                prompt = prompts[task_type]
                
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
        Build a prompt for the language model.
        
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
        self.logger.info("Shutting down local AI model")
        
        # Most PyTorch models don't need explicit cleanup,
        # but we can free memory if using CUDA
        if hasattr(self, 'llm') and self.llm is not None:
            try:
                import torch
                if hasattr(self.llm, "to"):
                    self.llm.to("cpu")
                torch.cuda.empty_cache()
            except (ImportError, AttributeError):
                pass