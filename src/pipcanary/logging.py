import logging

from logging import StreamHandler

from .errors import InvalidArgumentError


class BistreamHandler(StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            errstream = self.stream
            if record.levelno > 20:
                errstream.write(msg + self.terminator)
                self.flush()
            else:
                print(msg)
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


LOG_LEVELS = ["FATAL", "ERROR", "WARNING", "INFO", "DEBUG"]


def set_up_logging(format: str, level: str):
    if level not in LOG_LEVELS:
        raise InvalidArgumentError(
            "Invalid log level %s. Supported levels are: %s."
            % (level, ", ".join(LOG_LEVELS))
        )

    root = logging.getLogger()
    root.setLevel(level)

    for h in root.handlers[:]:
        root.removeHandler(h)
        h.close()

    handler = BistreamHandler()
    handler.setFormatter(logging.Formatter(format))
    root.addHandler(handler)
