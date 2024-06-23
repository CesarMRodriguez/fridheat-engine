class ApplicationState:

    def __init__(self):
        self.state = {}

    def add_value(self, name: str, value):
        self.state[name] = value

    def get_value(self, name: str):
        if not name in self.state:
            return None
        return self.state[name] 