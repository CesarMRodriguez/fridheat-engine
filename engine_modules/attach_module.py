
from typing import List

import frida
from application_state import ApplicationState
from engine_modules.module import Module
from frida_client import FridaClient


class AttachModule(Module):

    def __init__(self, frida_client: FridaClient, application_state: ApplicationState):
        super().__init__(module_name="attach", frida_client=frida_client, application_state=application_state)

    def set_command_format(self, command_dict: dict):
        command_dict[self.module_name] = {
                 'pid': None,
                 'process_name': None
            }
    
    def execute(self, user_input: List[str]):
        if len(user_input) != 3:
            print("Invalid attach command. Use 'attach pid <number>' or 'attach process_name <name>'.")
        
        attach_type = user_input[1]
        identifier = user_input[2]

        if attach_type == 'pid':
            try:
                identifier = int(identifier)
            except ValueError:
                print("Invalid PID. Please enter a valid number.")
                return False    

        return self.attach_to_process(attach_type, identifier)
        
    def attach_to_process(self, attach_type, identifier):
        
        if attach_type == 'pid':
            try:
                self.frida_client.attach_to_process_pid(identifier)
                print(f"Attached to process with PID {identifier}")
                self.application_state.add_value('attached_process',identifier)
            except frida.ProcessNotFoundError:
                print(f"No process found with PID {identifier}")
        
        elif attach_type == 'process_name':
            try:
                self.frida_client.attach_to_process(identifier)
                print(f"Attached to process with name {identifier}")
                self.application_state.add_value('attached_process',identifier)
            except frida.ProcessNotFoundError:
                print(f"No process found with name {identifier}")

        else:
            print(f"Input type {attach_type} is not valid, you have to use 'pid' or 'process_name'")            
            return False
        
        return True