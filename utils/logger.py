import logging

class Logger:
    def __init__(self, name=__name__):
        # Configure the logger
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(name)

    def d(self, message):
        self.logger.debug(message)

    def e(self, message):
        self.logger.error(message)

    def i(self, message):
        self.logger.info(message)

    def w(self, message):
        self.logger.warning(message)

    def c(self, message):
        self.logger.critical(message)