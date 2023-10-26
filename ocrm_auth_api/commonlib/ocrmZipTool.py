"""
# ===========================================================================
# ocrmZipTool.py
# ---------------------------------------------------------------------------
#
# This script contains useful data zip functions.
# Usage: import geomartZipTool
#        Then call a function in this script
#
# ===========================================================================
"""

import zipfile
import os

print("Loading ocrmZipTool libraries")

class ZipTool:
    """
        Support class for zip and unzip file
    """ 
    def __init__(self, zipPath, zipAndcopyTo, logger):
        """
        constructor
        Args: zipPath: zip file path 
        zipAndcopyTo: zip and copy path
        logger: log file
        """
        try:
            self.zipPath = zipPath
            self.zipAndcopyTo = zipAndcopyTo
            self.logger = logger
        except Exception as e:
            raise Exception("ShapeToKML initialization failed.." , e)
        
        
    def ZipDir(self,src,out,zname,version,type):
        """
        create zip file
        Args: src: file/folder to be zip
        out: output zipped file location
        zname: Zipped file name
        type:.zip
        return: boolean
        """
        zipf = zipfile.ZipFile(os.path.join(out, zname+"_"+version+type), 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(src):
            if root == src:
                for file in files:
                    zipf.write(os.path.join(src, file),arcname=file)
        zipf.close()
    
    
    def WriteToZip(self, zipFilename, fileNamesToZip):
        """
        create zip file
        Args: zipFilename: zip file to be zip
        fileNamesToZip: output file name
        return: None
        """
        zipFile = os.path.join(self.zipPath ,zipFilename)
        zf = zipfile.ZipFile(zipFile,
                        mode='w',
                        compression=zipfile.ZIP_DEFLATED,
                        allowZip64=True)

        for file_name in fileNamesToZip:
            fileTozip = self.zipPath + '/' + file_name
            zf.write(fileTozip, arcname=file_name)

        zf.close()
        
    def zipAndCopy(self, sourcefgdbfolder, finalgdbzip, finalgdbname):
        """
        create zip file and copy to location
        Args: zipFilename: zip file to be zip 
        fileNamesToZip: output file name
        return: 0/1
        """
        try:
            
            myzipfile = zipfile.ZipFile(sourcefgdbfolder +"\\"+ finalgdbzip, 'w', zipfile.ZIP_DEFLATED)

            for root, dirs, files in os.walk(sourcefgdbfolder):
                # if root == sourcefgdbfolder + finalgdbname:
                for f in files:
                    myzipfile.write(root+'/'+f, arcname=finalgdbname+'/'+f)

            return(0)

        except Exception as e:
            print(e)       
            self.logger.printErrorMessage("ZipAndCopy failed..")
            return(1)

    def zipAndCopy2(self, sourcefgdbfolder,ziploc, finalgdbzip):
        """
        create zip file and copy to location
        Args: zipFilename: zip file to be zip 
        fileNamesToZip: output file name
        return: 0/1
        """
        try:
            
            myzipfile = zipfile.ZipFile(os.path.join(ziploc,finalgdbzip), 'w', zipfile.ZIP_DEFLATED)

            for root, dirs, files in os.walk(sourcefgdbfolder):
                if root == sourcefgdbfolder:
                    for f in files:
                        myzipfile.write(root+'/'+f, arcname=finalgdbzip+'/'+f)

            return(0)

        except Exception as e:
            print(e)       
            # self.logger.printErrorMessage("ZipAndCopy failed..")
            return(1)
        
    def zipDirectory(self, sourcefgdbfolder, finalgdbzip):
        """
        create zip file and copy to location
        Args: zipFilename: zip file to be zip 
        fileNamesToZip: output file name
        return: 0/1
        """
        try:
            
            myzipfile = zipfile.ZipFile(os.path.join(sourcefgdbfolder , finalgdbzip), 'w', zipfile.ZIP_DEFLATED)

            for root, dirs, files in os.walk(sourcefgdbfolder):
                if root == sourcefgdbfolder:
                    for f in files:
                        myzipfile.write(os.path.join(root,finalgdbzip))

            return(0)

        except Exception as e:
            print(e)       
            self.logger.printErrorMessage("ZipAndCopy failed..")
            return(1)
        
        
    def unzipFile(self, fileType):
        """
        unzip the file
        Args: fileType: file type to be unzip
        return: 0/1
        """
        try:
            if(not os.path.isfile(self.zipPath)):
                self.logger.printErrorMessage("Input file does not exist " + self.zipPath)
                return 1          

            extractPath = os.path.dirname(self.zipPath) #'\\'.join(self.zipPath.split('\\')[0:-1])
            self.logger.printInfoMessage(extractPath)
            
            with zipfile.ZipFile(self.zipPath, 'r') as zip_ref:
                zip_ref.extractall(extractPath)
            
            for zipFile in zip_ref.filelist:
                if(zipFile.filename.lower().endswith(fileType)):
                    return 0, extractPath + '/' + zipFile.filename

            self.logger.printErrorMessage("Input file type not found in zip file")
            return 1, None
        except Exception as e:
            self.logger.printErrorMessage("Error in UnZiping File " + str(e))        
            return 1