"""
# ===========================================================================
#geomartConfigTool.py
# ---------------------------------------------------------------------------
#
# This script contains useful config read functions.
# Usage: import geomartConfigTool
#        Then call a function in this script
#
# ===========================================================================
"""
import datetime

print("Loading geomartConstant libraries")

class EmailConstants:
    """
        Email Template for gdinspect
    """
    dataRefreshFromEmail = "rkmr@pge.com"
    dataRefreshSuccessEmailList = ["gtinspect_Core_Development_Team@PGE.onmicrosoft.com" , "GoeMartOnMSupport@pge.com" , "GeoMart_CloudGISCOE@PGE.onmicrosoft.com" , "j0m0@pge.com"]
    dataRefresFailedEmailList = ["rkmr@pge.com"]
    now = datetime.datetime.now()
    execTime = now.strftime("%Y-%m-%d")

    dataRefreshSuccessBody = '''
    <html>
    <head></head>
    <body>
     <p style="color: red;">This is Automatic generated email after completing gdinspect Data Refresh!!</p>

    <p>
    Hi All,</br>
     gdinspect Data Refresh completed successfully on ''' + execTime + '''. </br>
    </br>
    Thanks,</br>
    gdinspect Core Development team </p>
        
    </body>
    </html>
    '''

    dataRefreshFailedBody = '''
    <html>
    <head></head>
    <body>
     <p style="color: red;">This is Automatic generated email after completing gtgis Data Refresh!!</p>

    <p>
    Hi All,</br>
    gtgis Data Refresh Failed during execution. See attached log on ''' + execTime + '''. </br>
    </br>
    Thanks,</br>
    gtgis Core Development team </p>
        
    </body>
    </html>
    '''
    dataRefreshSubject = "gtgis DataBase Refresh"
