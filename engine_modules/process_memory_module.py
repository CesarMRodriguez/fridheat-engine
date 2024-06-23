from typing import List
from application_state import ApplicationState
from engine_modules.module import Module
from frida_client import FridaClient


class ProcessMemoryModule(Module):

    def __init__(self, frida_client: FridaClient, application_state: ApplicationState):
        super().__init__(module_name="show_memory", frida_client=frida_client, application_state=application_state)
        self.started = False

    def set_command_format(self, command_dict: dict):
        command_dict[self.module_name] = {
            "all": None,
            "active": None,
            "filter_by_name": None,
            "filter_by_range": None,
            "reset_memory_pages": None,
            "restart_active_pages": None
        }
    
    def execute(self, user_input: List[str]):
        attached_process = self.application_state.get_value('attached_process')
        if attached_process is None:
            print("No process attached.")
        else:
            if not self.started:
                rpc = self.frida_client.get_rpc_exports()
                rpc.start_memory_pages()
                self.started = True

            action = user_input[1]
            if action == "all":
                memory_pages = self.get_all_memory_pages()
                self.show_memory_pages(memory_pages)
            elif action == "active":
                memory_pages = self.get_active_memory_pages()
                self.show_memory_pages(memory_pages)
            elif action == "filter_by_name":
                if len(user_input) != 3:
                    print("filter_by_name requires only one parameter")
                else:
                    memory_pages = self.filter_pages_by_name(user_input[2])
                    self.show_memory_pages(memory_pages)
            elif action == "filter_by_range":
                if len(user_input) != 4:
                    print("filter_by_range requires only one parameter")
                else:
                    memory_pages = self.filter_pages_by_range(user_input[2],user_input[3])
                    self.show_memory_pages(memory_pages)
            elif action == "reset_memory_pages":
                memory_pages = self.restart_memory_pages()
                self.show_memory_pages(memory_pages)
            elif action == "restart_active_pages":
                memory_pages = self.restart_active_pages()
                self.show_memory_pages(memory_pages)

        return True

    def restart_active_pages(self):
        rpc = self.frida_client.get_rpc_exports()  

        rpc.reset_visibility_memory_pages()
        memory_pages = rpc.get_active_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)    

    def restart_memory_pages(self):
        rpc = self.frida_client.get_rpc_exports()  

        rpc.restart_memory_pages()
        memory_pages = rpc.get_active_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)        

    def show_memory_pages(self, memory_pages):
        
        if (len(memory_pages) == 0):
            print("no memory pages to show")
            return
        
        max_name_length = max(len(page['name']) for page in memory_pages)

        print(f"{'Page Name':<{max_name_length + 2}} {'Init Address':<15} {'End Address':<15} {'Filter':<10}")
        for page in memory_pages:
            filter_flag = 'T' if page['filter'] else 'F'
            print(f"{page['name']:<{max_name_length + 2}} {page['init_address']:<15} {page['end_address']:<15} {filter_flag:<10}")

    def get_active_memory_pages(self):
        # Dummy data for example purposes
        rpc = self.frida_client.get_rpc_exports()  

        memory_pages = rpc.get_active_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)
    
    def filter_pages_by_name(self, file_name_pattern: str):
        rpc = self.frida_client.get_rpc_exports()  
        rpc.filter_by_file_name(file_name_pattern)
        
        memory_pages = rpc.get_active_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)

    def filter_pages_by_range(self, init_range: str, end_range: str):
        rpc = self.frida_client.get_rpc_exports()  
        rpc.filter_by_memory_range(init_range, end_range)
        
        memory_pages = rpc.get_active_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)


    def get_all_memory_pages(self):
        # Dummy data for example purposes
        rpc = self.frida_client.get_rpc_exports()

        memory_pages = rpc.get_all_memory_pages()
        return self.convert_memory_ranges_to_pages(memory_pages)

    def convert_memory_ranges_to_pages(self, memory_ranges):
        memory_pages = []

        if memory_ranges == None:
            return memory_pages
        
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

