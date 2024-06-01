class NoProcessLaunchedException(Exception):

    def __init__(self, package_name):
        super().__init__(f"The package name {package_name} was not running")
        self.error_code = 100