
import sys
from frida_client import FridaClient

if __name__ == "__main__":

    frida = FridaClient()

    processes = frida.get_process_list()

    frida.attach_to_process_pid(3022)

    # for process in processes:
    #     print(f"PID: {process.pid}, Name: {process.name}")

    js_code = """
    var a = 12;

    Java.perform(function () {
        const ExampleClass = Java.use("com.advanced.android.testmultibanditserialization.ExampleClass");
        ExampleClass.testFridaMethod.implementation = function () {
            a+= 1;
            send("Send message " + a);
            this.testFridaMethod();
        }
    });
    """

    js_code2 = """
    Java.perform(function () {
        const ExampleClass = Java.use("com.advanced.android.testmultibanditserialization.ExampleClass");
        ExampleClass.testFridaMethod2.implementation = function () {
            send("Send message " + a);
            this.testFridaMethod2();
        }
    });
    """

    #frida.add_script(js_code=js_code)
    #frida.add_script(js_code=js_code2)    

    rpc = frida.get_rpc_exports()

    rpc.start_memory_pages()

    memory_pages = rpc.get_all_memory_pages()
    for page in memory_pages:
        print(page)
         
    print("[*] Script loaded successfully")

    # # Keep the script running
    # sys.stdin.read()