from datetime import datetime
import pytz  

def getesttime():
    """This function is to get current time for US/Eastern

    Raises:
        Exception: _description_

    Returns:
        Time: return current time for 
    """
    try:
        timezone="US/Eastern"
        date=datetime.now(tz=pytz.utc)
        return date.astimezone(pytz.timezone(timezone))
    except Exception as e:
        print("Failed to run getesttime function ..",str(e)) 
        raise Exception(e)