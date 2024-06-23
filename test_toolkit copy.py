import frida
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
import asyncio
from abc import ABC, abstractmethod

from engine_modules.module_administrator import ModuleAdministrator
from frida_client import FridaClient

class Application(ABC):
    def __init__(self):
        self.process_list = []
        self.attached_process = None
        self.module_administrator = ModuleAdministrator()

    @abstractmethod
    def get_process_list(self):
        """
        Abstract method to get the process list.
        Should be implemented to update self.process_list.
        """
        pass

    @abstractmethod
    def attach_to_process(self, attach_type, identifier):
        """
        Abstract method to attach to a process by PID or name.
        """
        pass

    @abstractmethod
    def get_memory_pages(self, pid):
        """
        Abstract method to get the memory pages of a process.
        """
        pass

    async def run(self):
        session = PromptSession()

        commands = NestedCompleter.from_nested_dict(self.module_administrator.get_command_format_list())
        # commands = NestedCompleter.from_nested_dict({
        #     'process_list': None,
        #     'attach': {
        #         'pid': None,
        #         'process_name': None
        #     },
        #     'show_memory': None,
        #     'exit': None
        # })

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
                
                ##TODO: remove later
                if main_command == 'process_list':
                    self.process_list = self.get_process_list()
                    self.show_process_list()
                
                elif main_command == 'attach':
                    if len(parts) != 3:
                        print("Invalid attach command. Use 'attach pid <number>' or 'attach process_name <name>'.")
                        continue
                    
                    attach_type = parts[1]
                    identifier = parts[2]

                    if attach_type == 'pid':
                        try:
                            identifier = int(identifier)
                        except ValueError:
                            print("Invalid PID. Please enter a valid number.")
                            continue

                    self.attach_to_process(attach_type, identifier)
                    self.attached_process = identifier
                
                elif main_command == 'show_memory':
                    if self.attached_process is None:
                        print("No process attached.")
                    else:
                        memory_pages = self.get_memory_pages(self.attached_process)
                        self.show_memory_pages(memory_pages)
                
                elif main_command == 'exit':
                    print("Exiting...")
                    break
                
                else:
                    print("Unknown command")
            
            except (EOFError, KeyboardInterrupt):
                break

    def show_process_list(self):
        print(f"{'PID':<10} {'Description'}")
        for proc in self.process_list:
            print(f"{proc['pid']:<10} {proc['description']}")

    def show_memory_pages(self, memory_pages):
        
        max_name_length = max(len(page['name']) for page in memory_pages)

        print(f"{'Page Name':<{max_name_length + 2}} {'Init Address':<15} {'End Address':<15} {'Filter':<10}")
        for page in memory_pages:
            filter_flag = 'T' if page['filter'] else 'F'
            print(f"{page['name']:<{max_name_length + 2}} {page['init_address']:<15} {page['end_address']:<15} {filter_flag:<10}")

class MyApplication(Application):

    def __init__(self):
        super().__init__()
        self.frida_client = FridaClient()
        
    def get_process_list(self):
        # Dummy data for example purposes
        processes = self.frida_client.get_process_list()

        process_to_show = []

        for process in processes:
            process_to_show.append({'pid': process.pid, 'description': process.name})

        return process_to_show

    def attach_to_process(self, attach_type, identifier):
        
        if attach_type == 'pid':
            try:
                self.frida_client.attach_to_process_pid(identifier)
                print(f"Attached to process with PID {identifier}")
            except frida.ProcessNotFoundError:
                print(f"No process found with PID {identifier}")
        
        elif attach_type == 'process_name':
            try:
                self.frida_client.attach_to_process(identifier)
                print(f"Attached to process with name {identifier}")
            except frida.ProcessNotFoundError:
                print(f"No process found with name {identifier}")

    def convert_memory_ranges_to_pages(self, memory_ranges):
        memory_pages = []

        for idx, range_entry in enumerate(memory_ranges):
            base_address = int(range_entry['rangeDetails']['base'], 16)
            size = range_entry['rangeDetails']['size']
            end_address = base_address + size - 1
            protection = range_entry['rangeDetails']['protection']
            enabled = range_entry['enabled']

            if "file" in range_entry['rangeDetails']:
                page_name = range_entry['rangeDetails']["file"]["path"]
            else:
                page_name = f"Page {idx + 1}"
            filter_flag = enabled

            memory_page = {
                'name': page_name,
                'init_address': f"0x{base_address:08X}",
                'end_address': f"0x{end_address:08X}",
                'filter': filter_flag
            }

            memory_pages.append(memory_page)

        return memory_pages

    def get_memory_pages(self, pid):
        # Dummy data for example purposes
        rpc = self.frida_client.get_rpc_exports()

        rpc.start_memory_pages()

        memory_pages = rpc.get_all_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)

if __name__ == '__main__':
    app = MyApplication()
    asyncio.run(app.run())