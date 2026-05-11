import logging

from logging import StreamHandler


class BiStreamHandler(StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            error_stream = self.stream
            if record.levelno > 20:
                error_stream.write(msg + self.terminator)
                self.flush()
            else:
                print(msg)
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


LOG_LEVELS = ["FATAL", "ERROR", "WARNING", "INFO", "DEBUG"]


def set_up_logging(format: str, level: str):
    root = logging.getLogger()
    root.setLevel(level)

    for h in root.handlers[:]:
        root.removeHandler(h)
        h.close()

    handler = BiStreamHandler()
    handler.setFormatter(logging.Formatter(format))
    root.addHandler(handler)
