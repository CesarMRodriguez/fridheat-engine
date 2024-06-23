import frida
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
import asyncio

from application_state import ApplicationState
from engine_modules.module_administrator import ModuleAdministrator
from frida_client import FridaClient

class Application:
    def __init__(self):
        self.process_list = []
        self.frida_client = FridaClient()
        self.application_state = ApplicationState()
        self.module_administrator = ModuleAdministrator(self.frida_client, self.application_state)

    async def run(self):
        session = PromptSession()

        my_command_dict = self.module_administrator.get_command_format_list()
        
        #Add non module administred commands
        my_command_dict['exit'] = None
        commands = NestedCompleter.from_nested_dict(my_command_dict)

        while True:
            try:
                with patch_stdout():
                    command = await session.prompt_async('> ', completer=commands)
                
                parts = command.strip().split()
                if not parts:
                    continue
                main_command = parts[0]

                if main_command == 'exit':
                    print("Exiting...")
                    break  
                else:
                    results = self.module_administrator.execute_command(parts)
                    if results == None:
                        print("Unknown command")
            
            except (EOFError, KeyboardInterrupt):
                break

if __name__ == '__main__':
    app = Application()
    asyncio.run(app.run())