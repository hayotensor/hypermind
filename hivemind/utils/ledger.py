import logging

class LoggerLedger:
  LEDGER_LEVEL = 25

  def __init__(self, log_file="debug.log"):
    logging.addLevelName(self.LEDGER_LEVEL, "LEDGER")
    logging.Logger.log_ledger = self.log_ledger

    self.logger = logging.getLogger(__name__)
    self.logger.propagate = False

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(self.LEDGER_LEVEL)
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)

    self.logger.addHandler(file_handler)

  def log_ledger(self, message, *args, **kwargs):
    if self.logger.isEnabledFor(self.LEDGER_LEVEL):
      self.logger._log(self.LEDGER_LEVEL, message, args, **kwargs)

  def get_logger(self):
    return self.logger

"""
Use logger_ledger.log_ledger() to add logs to debug.log
"""
logger_ledger = LoggerLedger().get_logger()
