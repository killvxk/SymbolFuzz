import logging
import hashlib


"""
Define basic exception class
"""
class UnsupportArchException(Exception):
    def __init__(self, arch):
        Exception.__init__(self, "Architecture %s is not supported yet" % arch)


class NotImplementedException(Exception):
    def __init__(self, arch):
        Exception.__init__(self, "Sorry, this part is not implemented yet")

##############################################################################
"""
Define some basic functions
"""
def get_logger(module_name, log_level=logging.DEBUG):
    global gLoglevel

    fmt = '{} %(levelname)s: %(message)s'.format(module_name)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(fmt))
    logger = logging.getLogger(module_name)
   
    logger.setLevel(log_level)
    if not logger.handlers:
        logger.addHandler(console_handler)

    return logger


def title(msg, obj=None, length=70, fill='='):
    """ Print debug information """
    msg = ' ' + msg + ' '
    msg = fill * ((length-len(msg))/2) + msg
    print msg.ljust(length, fill)
    if obj != None:
        print obj

def memoize(f):
    cached = {}

    def helper(*args, **kargs):

        key = (args, tuple(kargs.values()))
        if key not in cached:
            cached[key] = f(*args, **kargs)
        return cached[key]

    return helper

@memoize
def md5(stream, is_file=True):
    """ Generate md5 for file or string """
    md5 = hashlib.md5()
    if is_file:
        data = open(stream).read()
        md5.update(data)
    else:
        md5.update(stream)

    return md5.hexdigest()


"""
Just for local debug
"""
def connectPycharm(ip, port=4444):
    try:
        import sys
        sys.path.append('/data/pydev')
        import pydevd
        pydevd.settrace(ip, port=port, stdoutToServer=True, stderrToServer=True)
    except Exception as e:
        print(e)
        print("failed to load pycharm debugger")
