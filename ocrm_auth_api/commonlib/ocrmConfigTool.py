"""
 ocrmConfigTool.py
 ---------------------------------------------------------------------------

 This script contains useful config read functions.
 Usage: import ocrmConfigTool
        Then call a function in this script

"""

import json

print("Loading ocrmConfigTool libraries")

class ConfigTool:
    """
        Support class for reading configuration
    """

    def __init__(self, environment, configPathWithName):
        """
            constructor
            @args
            environment: LOCAL --> allows local debug
            configPathWithName: Configuration file name
        """
        try:
            self.environment = environment
            self.configPath = configPathWithName

        except Exception as e:
            raise Exception("ConfigTool initialization failed..", e)

    def getConfig(self):
        """
            get configuration from file
            return: configuration keys
        """
        try:
            with open(self.configPath, encoding='utf-8-sig') as outfile:
                jObj = json.loads(outfile.read())

            if(jObj is not None):
                keys = jObj.get(self.environment, None)
                return keys

        except Exception as e:
            raise Exception("ConfigTool initialization failed..", e)
