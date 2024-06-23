from application_state import ApplicationState
from engine_modules.attach_module import AttachModule
from engine_modules.module import Module
from engine_modules.process_memory_module import ProcessMemoryModule
from engine_modules.process_module import ProcessModule
from frida_client import FridaClient
from utils.logger import Logger
from typing import List

logger = Logger(__name__)

class ModuleAdministrator:

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ModuleAdministrator, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, frida_client: FridaClient, application_state: ApplicationState):
        if self._initialized:
            return
        self.modules: List[Module] = []
        self.application_state = application_state
        self.modules.append(ProcessModule(frida_client=frida_client, application_state=application_state))
        self.modules.append(AttachModule(frida_client=frida_client, application_state=application_state))
        self.modules.append(ProcessMemoryModule(frida_client=frida_client, application_state=application_state))
        self._initialized = True

    def get_command_format_list(self) -> dict:
        command_dict = {}
        for module in self.modules:
            module.set_command_format(command_dict)

        logger.d(f"Command dict generated: {command_dict}")
        return command_dict
    
    def execute_command(self, user_input: List[str]):
        command_to_execute = user_input[0]
        for module in self.modules:
            if module.is_command(command_to_execute):
                return module.execute(user_input)
            
        return None
    


