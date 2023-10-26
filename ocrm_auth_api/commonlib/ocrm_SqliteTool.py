"""
    DB class
"""
import os
import sqlite3


class CreateSqliteDBConnection:
    """
        Create connection to db
    """
    
    def __init__(self,id="",projectname="",tms="",action="",email="",status="",message="",insertstatusdate="",updatestatusdate="",attachmentname="",originalattachment="",filetype=""):
        """
            constructor
            Logger - Logger file
        """
        try:            
            self.id=id
            self.projectname=projectname
            self.tms=tms
            self.action=action
            self.email=email
            self.status=status
            self.message=message
            self.insertstatusdate=insertstatusdate
            self.updatestatusdate=updatestatusdate
            self.attachmentname=attachmentname
            self.originalattachment=originalattachment
            self.filetype=filetype
        except Exception as e:
            raise Exception("Error while initaiting db object..." , e)
        
    def connectdb(self,logger,dbpath):
        try:
            self.logger = logger
            self.db=sqlite3.connect(dbpath)
            return self
        except Exception as e:
            raise Exception("Error while connecting to db..." , e)
       

    def insert_in_db(self,query):
        """
        return: None
        """
        try:
           cursor=self.db.execute(query)
           cursor.connection.commit()
        except Exception as e:
            if (self.logger != None):
                self.logger.printErrorMessage('Failed to insert data! -' +str(e))
            return 1, None
        finally:
            cursor.close()
            self.db.close()
     
    @classmethod       
    def select_one_from_db(cls,query,itemId,dbFullPath,logger):
        """
        return: None
        """
        try:
            conn=cls.connectdb(cls,logger,dbFullPath)
            cursor=conn.db.cursor()
            cursor.execute(query,(itemId,))
            row=cursor.fetchone()
            if row:
                item= cls(*row)
                return [item.__dict__]
            else:
                return []
         
        except Exception as e:
            print(str(e))
            if (cls.logger != None):
                cls.logger.printErrorMessage('Getting job from db failed! -' +str(e))
            return 1, None
        finally:
            cursor.close()
            cls.db.close()
       
       
    @classmethod       
    def select_all_from_db(cls,query,dbFullPath,logger):
        """
        return: None
        """
        try:
            boundarylist=[]
            conn=cls.connectdb(cls,logger,dbFullPath)
            cursor=conn.db.cursor()
            cursor.execute(query)
            rows=cursor.fetchall()
            if rows:
                for row in rows:
                    item= cls(*row)
                    boundarylist.append(item.__dict__.copy())
                return boundarylist
            else:
                return []
         
        except Exception as e:
            print(str(e))
            if (cls.logger != None):
                cls.logger.printErrorMessage('Sending email failed! -' +str(e))
            return 1, None
        finally:
            cursor.close()
            cls.db.close()               
