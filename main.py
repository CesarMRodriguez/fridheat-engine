
import sys
from frida_client import FridaClient

if __name__ == "__main__":

    frida = FridaClient("com.advanced.android.testmultibanditserialization")

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

    print(rpc.read_variable())
    rpc.write_variable(8)
    print(rpc.read_variable())
    print("[*] Script loaded successfully")

    # Keep the script running
    sys.stdin.read()