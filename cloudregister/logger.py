# Copyright (c) 2025, SUSE LLC, All rights reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.
#
import logging
import logging.handlers
import sys


class Logger:
    """
    Setup logging for stdout, stderr and logfile
    """
    def __init__(self):
        # change log level to NOTSET for init
        logging.getLogger().setLevel(logging.NOTSET)

        formatter = logging.Formatter(
            '%(asctime)s: %(levelname)s: %(message)s'
        )

        # Add stdout handler, with level INFO
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console.addFilter(lambda record: record.levelno <= logging.WARNING)
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)

        # Add error handler, with level ERROR
        error = logging.StreamHandler(sys.stderr)
        error.setLevel(logging.ERROR)
        error.setFormatter(formatter)
        logging.getLogger().addHandler(error)

    def set_logfile(self, logfile, debug=False):
        # Add file handler, with level DEBUG (all)
        formatter = logging.Formatter(
            '%(asctime)s: %(module)s: %(lineno)s '
            '%(funcName)s: %(levelname)s: %(message)s'
        )
        logfile = logging.FileHandler(filename=logfile, encoding='utf-8')
        if debug:
            logfile.setLevel(logging.DEBUG)
        else:
            logfile.setLevel(logging.INFO)
        logfile.setFormatter(formatter)
        logging.getLogger().addHandler(logfile)

    @staticmethod
    def get_logger():
        return logging.getLogger("app." + __name__)
