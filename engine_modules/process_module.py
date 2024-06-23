from typing import List
from application_state import ApplicationState
from engine_modules.module import Module
from frida_client import FridaClient


class ProcessModule(Module):

    def __init__(self, frida_client: FridaClient, application_state: ApplicationState):
        super().__init__(module_name="process_list", frida_client=frida_client, application_state=application_state)

    def set_command_format(self, command_dict: dict):
        command_dict[self.module_name] = None
    
    def execute(self, user_input: List[str]):
        process_list = self.get_process_list()
        self.show_process_list(process_list)        
        
        return True

    def get_process_list(self) -> list:
        # Dummy data for example purposes
        processes = self.frida_client.get_process_list()

        process_to_show = []

        for process in processes:
            process_to_show.append({'pid': process.pid, 'description': process.name})

        return process_to_show
    
    def show_process_list(self, process_list: list):
        print(f"{'PID':<10} {'Description'}")
        for proc in process_list:
            print(f"{proc['pid']:<10} {proc['description']}")
