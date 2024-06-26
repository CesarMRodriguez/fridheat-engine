import frida

from exceptions.frida_client_exceptions import NoProcessLaunchedException

_SCRIPT_FILENAME = 'core/_agent.js'

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    else:
        print(message) 

class FridaClient:

    def __init__(self):
        self.package_name = ''

        #scripts
        self.added_scripts = []

        #attach frida to application
        self.device = frida.get_usb_device()

    def get_process_list(self) -> list:
        processes = self.device.enumerate_processes()

        #Key information PID: {process.pid}, Name: {process.name}
        return processes

    def attach_to_process_pid(self, pid: int):
        #scripts
        self.added_scripts = []

        self.session = self.device.attach(pid)
        with open(_SCRIPT_FILENAME, 'r', encoding='utf-8') as script_file:
            self.code = script_file.read()

        script = self.session.create_script(self.code)
        script.on('message', on_message)
        script.load()
        self.added_scripts.append(script)  

    def attach_to_process(self, package_name: str):
        self.package_name = package_name

        #scripts
        self.added_scripts = []

        #attach frida to application
        self.device = frida.get_usb_device()
        process_pid = self._get_pid_by_package_name(device=self.device, package_name=package_name)
        if process_pid == 0:
            raise NoProcessLaunchedException("No launched process")
        self.session = self.device.attach(process_pid)
        with open(_SCRIPT_FILENAME, 'r') as script_file:
            self.code = script_file.read()

        script = self.session.create_script(self.code)
        script.on('message', on_message)
        script.load()
        self.added_scripts.append(script)        

    def _get_pid_by_package_name(self, device, package_name):
        applications = device.enumerate_applications()
        for application in applications:
            if application.identifier == package_name:
                return application.pid

    def get_rpc_exports(self):
        return self.added_scripts[0].exports

    def add_script(self, js_code: str):

        self.added_scripts.append(js_code)
        # Load the JavaScript code
        script = self.session.create_script(js_code)

        # Set a message handler
        script.on('message', on_message)

        # Load and execute the script
        script.load()