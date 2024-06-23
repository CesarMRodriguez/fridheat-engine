from abc import ABC, abstractmethod
from typing import List

from application_state import ApplicationState
from frida_client import FridaClient

class Module:

    def __init__(self, module_name: str, frida_client: FridaClient, application_state: ApplicationState):
        self.module_name = module_name
        self.frida_client = frida_client
        self.application_state = application_state

    @abstractmethod
    def set_command_format(self, command_dict: dict):
        pass

    def is_command(self, command_to_execute: str) -> bool:
        return self.module_name == command_to_execute 
    
    @abstractmethod
    def execute(self, user_input: List[str]):
        pass