"""
Template manager for handling email templates.
"""

import os
from typing import Dict, Any

class TemplateManager:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        
    def _read_template(self, template_name: str) -> str:
        """
        Read a template file and return its contents.
        
        Args:
            template_name (str): Name of the template file
            
        Returns:
            str: Template contents
            
        Raises:
            FileNotFoundError: If template file doesn't exist
        """
        template_path = os.path.join(self.template_dir, template_name)
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
            
    def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Render a template with the given context.
        
        Args:
            template_name (str): Name of the template file
            context (Dict[str, Any]): Variables to inject into the template
            
        Returns:
            str: Rendered template
            
        Raises:
            FileNotFoundError: If template file doesn't exist
            KeyError: If required context variables are missing
        """
        template_content = self._read_template(template_name)
        return template_content.format(**context)

# Singleton instance
template_manager = TemplateManager()
