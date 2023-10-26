"""
# ===========================================================================
#geomartLoggerTool.py
# ---------------------------------------------------------------------------
#
# This script contains useful Logger read/write functions.
# Usage: import geomartLoggerTool
#        Then call a function in this script
#
# ===========================================================================
"""

import os
import datetime
import logging

print("Loading geomartLogger libraries")

class LoggerTool:
    """
        Support class for reading configuration
    """
    def __init__(self, loggerPath, loggerName, appendtolog="", logDelete=False, logMessage=True):
        """
        constructor
        Args: loggerPath: Log file path
        loggerName: Log file name
        appendtolog:Existing log file path.
        logDelete=False,
        logMessage=True
        """
        try:
            writemode="w"
            if(not logMessage):
                self.loggerToolObj = None
                self.logMessage = logMessage
                return

            now = datetime.datetime.now()

            if not os.path.exists(loggerPath):
                os.makedirs(loggerPath)
                
            if appendtolog!="":
                logFileName=appendtolog
                writemode="a"
            else:  
                
                if not logDelete:
                    logFileName = loggerName + now.strftime("%Y-%m-%d %H-%M") + '.log'
                else:
                    logFileName = loggerName
                    if os.path.exists(loggerPath + logFileName):
                        os.remove(loggerPath + logFileName)

            loggerToolObj = logging.getLogger(logFileName)
            hdlr = logging.FileHandler(loggerPath + "\\" + logFileName , mode=writemode)
            formatter = logging.Formatter('%(asctime)s:   %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
            hdlr.setFormatter(formatter)
            loggerToolObj.addHandler(hdlr)
            loggerToolObj.setLevel(logging.DEBUG)
            self.loggerToolObj = loggerToolObj
            self.logMessage = logMessage
            self.logFileName = logFileName
            self.loggerPath = loggerPath
        except Exception as e:
            print("loggerTool initialization failed.."+ e.args[0])

    def printInfoMessage(self, message):
        """
        function to print message and log in to log file
        Args: message: message to be print
        return: None
        """
        try:
            now = datetime.datetime.now()
            message = str(message) + " " + now.strftime("%Y-%m-%d %H:%M")
            print(message)

            if(self.logMessage):
                self.loggerToolObj.info(message)

        except Exception as e:
            print("loggerTool failed in printInfoMessage.."+ e.args[0])
            self.loggerToolObj.error("loggerTool failed in printInfoMessage.."+ e.args[0])

    def printErrorMessage(self, message):
        """
        function to print error message and log in to log file
        Args: message: Error message to be print
        return: None
        """
        try:
            now = datetime.datetime.now()
            message = str(message) + " " + now.strftime("%Y-%m-%d %H:%M")
            print(message)

            if(self.logMessage):
                self.loggerToolObj.error(message)

        except Exception as e:
            print("loggerTool failed in printErrorMessage.." + e.args[0])
            self.loggerToolObj.error("loggerTool failed in printErrorMessage.." + e.args[0])

    def getLoggerPathAndFileName(self):
        """
        return log file path and name
        """
        return self.loggerPath + self.logFileName
