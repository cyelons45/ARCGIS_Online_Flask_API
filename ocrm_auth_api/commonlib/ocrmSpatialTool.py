"""
# ===========================================================================
#ocrmSpatialTool.py
# ---------------------------------------------------------------------------
#
# This script contains useful spatial data file handle functions.
# Usage: import spatialProcessTool
#        Then call a function in this script
#
# ===========================================================================
"""

from datetime import datetime
import pandas as pd
import arcpy

print("Loading SpatialProcessTool libraries")

class SpatialProcessTool:
    """
        Support class for Export data
    """
    def __init__(self, logger):
        """
        constructor
        Args: logger: log file
        """
        try:            
            self.logger = logger
        except Exception as e:
            raise Exception("spatialProcessTool initialization failed.." , e)

    def copyFeaturelayerFieldProjectSource(self, queryParameter, fieldinfo, sourceFeature, outputPath, targetFeature, targetFields, needFGDB, needCSV, input_delimiter, projectToLatLong=True):
        """
        Copy Feature Layer in to GDB and CSV format
        Args:   queryParameter (string) - sql query
                fieldinfo: out put field information
                sourceFeature: source feature class
                outputPath: output location
                targetFeature: output feature layer name
                targetFields: output feature layer fields
                needFGDB: output in FGDB
                needCSV: output in CSV
                input_delimiter: Delimiter for CSV format
                projectToLatLong: projection
            return: True/False
        """
        try:
            endtime = datetime.now()
            if needFGDB:
                #project_coordiante = arcpy.Describe(sourceFeature).SpatialReference.exporttostring()
                project_coordiante = arcpy.SpatialReference()
                utm_proj_string = "PROJCS['NAD_1983_UTM_Zone_10N',GEOGCS['GCS_North_American_1983',DATUM['D_North_American_1983',SPHEROID['GRS_1980',6378137.0,298.257222101]],PRIMEM['Greenwich',0.0],UNIT['Degree',0.0174532925199433]],PROJECTION['Transverse_Mercator'],PARAMETER['False_Easting',500000.0],PARAMETER['False_Northing',0.0],PARAMETER['Central_Meridian',-123.0],PARAMETER['Scale_Factor',0.9996],PARAMETER['Latitude_Of_Origin',0.0],UNIT['Meter',1.0]]", "", "PROJCS['NAD_1983_UTM_Zone_10N',GEOGCS['GCS_North_American_1983',DATUM['D_North_American_1983',SPHEROID['GRS_1980',6378137.0,298.257222101]],PRIMEM['Greenwich',0.0],UNIT['Degree',0.0174532925199433]],PROJECTION['Transverse_Mercator'],PARAMETER['False_Easting',1640416.666666667],PARAMETER['False_Northing',0.0],PARAMETER['Central_Meridian',-123.0],PARAMETER['Scale_Factor',0.9996],PARAMETER['Latitude_Of_Origin',0.0],UNIT['Foot_US',0.3048006096012192]]"
                project_coordiante.loadFromString(utm_proj_string)

                # Set overwrite option
                arcpy.env.overwriteOutput = True
                arcpy.env.outputCoordinateSystem = project_coordiante

                tempFeaturelayer = targetFeature +"_lyr"
                #tempFeaturelayer = os.path.basename(targetFeature) +"_lyr"
                arcpy.management.MakeFeatureLayer(sourceFeature, tempFeaturelayer, queryParameter, "", fieldinfo )
                self.logger.printInfoMessage("Process: Copy the Feature to FGDB")

                arcpy.management.CopyFeatures(tempFeaturelayer, targetFeature, "", "0", "0", "0")

                arcpy.Delete_management(tempFeaturelayer)
                
                elasptime = datetime.now() - endtime
                endtime =  datetime.now()
                self.logger.printInfoMessage("Done %s - to FGDB: %s minutes"%(targetFeature,round(elasptime.seconds/60,2)))

            if needCSV:

                if(projectToLatLong):
                    arcpy.env.outputCoordinateSystem = arcpy.SpatialReference(4326)
                else:
                    project_coordiante = arcpy.SpatialReference()
                    utm_proj_string = "PROJCS['NAD_1983_UTM_Zone_10N',GEOGCS['GCS_North_American_1983',DATUM['D_North_American_1983',SPHEROID['GRS_1980',6378137.0,298.257222101]],PRIMEM['Greenwich',0.0],UNIT['Degree',0.0174532925199433]],PROJECTION['Transverse_Mercator'],PARAMETER['False_Easting',500000.0],PARAMETER['False_Northing',0.0],PARAMETER['Central_Meridian',-123.0],PARAMETER['Scale_Factor',0.9996],PARAMETER['Latitude_Of_Origin',0.0],UNIT['Meter',1.0]]", "", "PROJCS['NAD_1983_UTM_Zone_10N',GEOGCS['GCS_North_American_1983',DATUM['D_North_American_1983',SPHEROID['GRS_1980',6378137.0,298.257222101]],PRIMEM['Greenwich',0.0],UNIT['Degree',0.0174532925199433]],PROJECTION['Transverse_Mercator'],PARAMETER['False_Easting',1640416.666666667],PARAMETER['False_Northing',0.0],PARAMETER['Central_Meridian',-123.0],PARAMETER['Scale_Factor',0.9996],PARAMETER['Latitude_Of_Origin',0.0],UNIT['Foot_US',0.3048006096012192]]"
                    project_coordiante.loadFromString(utm_proj_string)

                    arcpy.env.outputCoordinateSystem = project_coordiante

                output_csvfile = outputPath + '/' + targetFeature

                tempFeaturelayer = targetFeature +"_lyr"
                arcpy.management.MakeFeatureLayer(sourceFeature, tempFeaturelayer, queryParameter, "",None)

                arcpy.ExportXYv_stats(tempFeaturelayer, Value_Field=targetFields, Delimiter=input_delimiter[0], Output_ASCII_File=output_csvfile, Add_Field_Names_to_Output="ADD_FIELD_NAMES")

                elasptime = datetime.now() - endtime
                endtime =  datetime.now()
                self.logger.printInfoMessage("Done %s -to CSV: %s minutes"%(targetFeature, round(elasptime.seconds/60, 2)))

                arcpy.Delete_management(tempFeaturelayer)

                outputcsvfile = open(output_csvfile)
                outputcsv_count = len(outputcsvfile.readlines())

                self.logger.printInfoMessage("Done %s Copy CSV count: %s"%(targetFeature,outputcsv_count-1))
                
                count = targetFields.count(";") + 2 
                outputcsvfile = pd.read_csv(output_csvfile,sep=input_delimiter[1],encoding='utf-8',skipinitialspace=True, usecols=range(count))
                outputcsvfile.rename(columns={'XCoord': 'LONG', 'YCoord': 'LAT'},inplace=True)
                outputcsvfile = outputcsvfile[pd.notnull(outputcsvfile['LONG'])]
                outputcsvfile = outputcsvfile[pd.notnull(outputcsvfile['LAT'])]

                # outputcsvfile = outputcsvfile[outputcsvfile.LAT.apply(lambda x: x.is_integer())]
                # outputcsvfile = outputcsvfile[outputcsvfile.LONG.apply(lambda x: x.is_integer())]

                outputcsvfile.to_csv(output_csvfile, sep='\t', encoding='utf-8',index=False)
                self.logger.printInfoMessage("outputcsvfile count: %s"%(outputcsvfile.shape[0]))
                del output_csvfile
            return True

        except Exception as e:
            print(e)
            self.logger.printErrorMessage("Failed at copyFeaturelayerFieldProjectUTM10N " + str(e) )   
            return False