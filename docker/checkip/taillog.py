#!/usr/bin/env python

import time
import os
import logging

logger = logging.getLogger(__name__)

def follow(filename):
    '''generator function that yields new lines in a file
    '''
    # Jump to the end of the file
    filename.seek(0, os.SEEK_END)
    
    try:
        while True:
            line = filename.readline()
            if not line:
                time.sleep(0.1)
                continue

            yield line
    except (KeyboardInterrupt, SystemExit):
        logging.warning("Exiting the program.")
    except Exception:
        logger.exception("There was a problem following your file... {}".format(e))

def main():
    # Purely represenative. Change this to some relevant file to follow.
    filename = '/var/log/alternatives.log'

    logfile = open(filename,"r")

    for line in follow(logfile):
        print(line)

if __name__ == '__main__':
    try:
        exit(main())
    except Exception:
        logging.exception("Exception in main()")
        exit(1)
