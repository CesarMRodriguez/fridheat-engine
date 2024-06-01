import frida

from exceptions.frida_client_exceptions import NoProcessLaunchedException

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    else:
        print(message) 

class FridaClient:

    def __init__(self, package_name: str):
        self.package_name = package_name

        #scripts
        self.added_scripts = []

        #attach frida to application
        self.device = frida.get_usb_device()
        process_pid = self._get_pid_by_package_name(device=self.device, package_name=package_name)
        if process_pid == 0:
            raise NoProcessLaunchedException("No launched process")
        self.session = self.device.attach(process_pid)

    def _get_pid_by_package_name(self, device, package_name):
        applications = device.enumerate_applications()
        for application in applications:
            if application.identifier == package_name:
                return application.pid

    def add_script(self, js_code: str):

        self.added_scripts.append(js_code)
        # Load the JavaScript code
        script = self.session.create_script(js_code)

        # Set a message handler
        script.on('message', on_message)

        # Load and execute the script
        script.load()