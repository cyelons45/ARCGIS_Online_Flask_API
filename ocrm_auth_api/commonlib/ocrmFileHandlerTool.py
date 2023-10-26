"""
# ===========================================================================
# geomartZipTool.py
# ---------------------------------------------------------------------------
#
# This script contains useful data file handle functions.
# Usage: import geomartFileHandler
#        Then call a function in this script
#
# ===========================================================================
"""

import os
import shutil
import time
import glob
import io
import re
import sys
from subprocess import call

print("Loading geomartFileHandler libraries")

class FileHandlerTool:
    """
    Support class for File Handling Method
    """
    def __init__(self, logger):
        """
        constructor
        Args:
            logger: Logging File name
        """
        try:
            self.logger = logger
        except Exception as e:
            raise Exception("fileHandlerTool initialization failed.." , e)
        
        
    def copyLargeFiles(self, sourcePath, targetPath):
        """
        Copy files from source to nas drive
        Args:   sourcePath: source file path
                targetPath: target file path
            return: True/False
        """
        try:
            # check if the source path exist
            if(os.path.exists(sourcePath)):
                call(["xcopy", sourcePath, targetPath], shell=True)               
                return True
            else:
                return False
        except Exception as e:
            print("copy zipped file failed.." + e)
            self.logger.printErrorMessage("copy zipped file failed.." + str(e))
            raise Exception("copy files failed.." + e)

    def cleanDestination(self,targetPath):
        """
        Copy files from source to nas drive
        Args:   sourcePath: source file path
                targetPath: target file path
            return: True/False
        """
        try:
            # check if the source path exist
            if(os.path.exists(targetPath)):
             
                return True
            else:
                return False
        except Exception as e:
            print("copy zipped file failed.." + e)
            self.logger.printErrorMessage("copy zipped file failed.." + str(e))
            raise Exception("copy files failed.." + e)      
        
    def copyFiles(self, sourcePath, targetPath):
        """
        Copy files from source to destination
        Args:   sourcePath: source file path
                targetPath: target file path
            return: True/False
        """

        try:
            # check if the source path as read access and
            if (os.access(sourcePath, os.R_OK)
                and os.access(targetPath, os.W_OK)):
                files = glob.glob(sourcePath + "*")
                for f in files:
                    shutil.copy2(f, targetPath)
                
                return True
            else:
                return False

        except Exception as e:
            print("copy files failed.." + e)
            raise Exception("copy files failed.." + e)
               
    def moveFiles(self, sourcePath, targetPath):
        """
        move files from source to destination
        Args:   sourcePath: source file path
                targetPath: target file path
            return: True/False
        """
        try:
            # check if the source path as read access and
            # targetpath as read/ write access
            if (os.access(sourcePath, os.R_OK)
                    and os.access(targetPath, os.W_OK)):
                files = glob.glob(sourcePath + "*")
                for f in files:
                    shutil.move(f, targetPath)
                
                return True
            else:
                return False

        except Exception as e:
            print("Move files failed.." + e)
            raise Exception("move files failed.." + e)
           
    def deleteFiles(self, folderPath):
        """
        delete files from source 
        Args:   sourcePath: source folder path
                return: True/False
        """
        try:
            # check if the folder path as read write access
            if (os.access(folderPath, os.W_OK)):
                files = glob.glob(folderPath + "*")
                for f in files:
                    os.remove(f)
                return True
            else:
                return False

        except Exception as e:
            print("Delete files failed.." + e)
            raise Exception("Delete files failed.." + e)
           
    def deleteFile(self, filename):
        """
        delete files from source 
        Args:   sourcePath: source file path
                return: True/False
        """
        try:
            # check if the file exist 
            if os.path.isfile(filename):
                os.remove(filename)
                return True
            else:
                return True

        except Exception as e:
            raise Exception("Delete file failed.." 
            + e)
            
    def removeDoubleQuote(self, folderPath, searchFile):
        """
        # function to remove double quotes from the text files in a folder
        Args:   folderPath: source file path
                searchFile: filename
                return: None
        """

        try:
            path = folderPath + searchFile
            files = glob.glob(path)
            # iterate over the list getting each file
            for fle in files:
            # open the file and then call .read() to get the text
                with io.open(fle, 'r') as file:
                    content = file.read()
                    pattern = re.compile(r'".*?"', re.DOTALL)
                    content = pattern.sub(lambda x: x.group().replace('"', ''), content)
                # after the clean up,save the content to the csv file
                with io.open(fle, 'w') as file:
                    file.write(content)

        except Exception as e: 
            raise Exception("Remove Double Quote on files failed.." 
            + e)
    
    def removeASCIICode(self, folderPath, searchFile):
        """
            # function to remove double quotes from the text files in a folder
            Args:   folderPath: source file path
                    searchFile: filename
                return: None
        """
        try:
            path = folderPath + searchFile
            files = glob.glob(path)
            # iterate over the list getting each file
            for fle in files:
            # open the file and then call .read() to get the text
                with io.open(fle, 'r') as file:
                    content = file.read()
                    #content= content.replace('[^\x00-\x7F]+',' ')
                    content = re.sub(r'[^\x00-\x7F]+' , ' ', content)
                    pattern = re.compile(r'".*?"', re.DOTALL)
                    content= pattern.sub(lambda x: x.group().replace('\n', ''), content)
                    content= pattern.sub(lambda x: x.group().replace('|', ' '), content)

                # after the clean up, moving it to new location
                with io.open(fle, 'w') as file:
                    file.write(content)

        except Exception as e:
            raise Exception("Remove ASCII Code on files failed.." + e)

    def isFileLocked(self, filePath):
        """
        # check if file locked
        Args:   filePath: source file name
                return: 0/1
        """

        try:
            if(os.path.isfile(filePath)):

                tryCount = 0
                isAccess = False
                while(not isAccess):
                    try:
                        isAccess = os.access(filePath, os.W_OK)                      

                    except Exception as e:
                        self.logger.printErrorMessage("Try count - " + str(tryCount))
                        self.logger.printErrorMessage("Failed lock exist - " + str(e))
                        
                        time.sleep(30)
                        tryCount = tryCount + 1
                        if(tryCount == 10):
                            return 1
                    
            return 0
        except Exception as e:
            self.logger.printErrorMessage("Failed at isFileLocked - " + str(e))
            return 1

    def deleteDirectory(self, dirPath):
        """
        # Delete directory
        Args: dirPath: delete directory
            return 0/1
        """

        try:
            if(os.path.isdir(dirPath)):

                tryCount = 0
                isAccess = False

                while(not isAccess):
                    try:
                        shutil.rmtree(dirPath)                   
                        isAccess = True
                    except Exception as e:
                        self.logger.printErrorMessage("Try count - " + str(tryCount))
                        self.logger.printErrorMessage("Failed lock exist - " + str(e))
                        
                        time.sleep(30)
                        tryCount = tryCount + 1
                        if(tryCount == 10):
                            return 1
                    
            return 0
        except Exception as e:
            self.logger.printErrorMessage("Failed at isFileLocked - " + str(e))
            return 1