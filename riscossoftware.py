# Manages Local Downloads In The "software" Directories To The RISC OS Search Engine
# Developed by Rebecca Shalfield for The RISC OS Community
# Copyright (c) Rebecca Shalfield 2002-2013

import re, os, pymongo, sys, time, zipfile
from pymongo import Connection
from bson import ObjectId

class riscossoftware:

    def __init__(self):
        '''Initialisation settings'''

        # Connect to MongoDB on given host and port
        try:
            connection = Connection('localhost', 27017)
            self.mongodbPort = 27017
        except:
            connection = Connection('localhost', 27021)
            self.mongodbPort = 27021
        
        # Connect to 'riscos' database, creating if not already exists
        db = connection['riscos']
        
        # Connect to 'riscos' collection
        self.riscosCollection = db['riscos']    
    
        self.searchableAttributes = [
                                     ('Absolutes','absolutes'),
                                     ('Application Date','application_date'),
                                     ('Application Directory','application_directory'),
                                     ('Application Name','application_name'),
                                     ('Application Version','application_version'),
                                     ('ARC File','arc_file'),
                                     ('Author','author'),
                                     ('Categories','categories'),
                                     ('Copyright','copyright'),
                                     ('Description','description'),
                                     ('DTP Formats','dtp_formats'),
                                     ('Filetypes Read','filetypes_read'),
                                     ('Filetypes Set','filetypes_set'),
                                     ('Fonts','fonts'),
                                     ('Help','help'),
                                     ('Last Modified','last_modified'),
                                     ('License','license'),
                                     ('Maintainer','maintainer'),
                                     ('Minimum RISC OS Versions','minimum_riscos_versions'),
                                     ('Monitor Definition Files','monitor_definition_files'),
                                     ('Package Name','package_name'),
                                     ('Package Section','package_section'),
                                     ('Package Version','package_version'),
                                     ('Page Title','page_title'),
                                     ('Printer Definition Files','printer_definition_files'),
                                     ('Priority','priority'),
                                     ('Programming Languages','programming_languages'),
                                     ('Purpose','purpose'),
                                     ('Relocatable Modules','relocatable_modules'),
                                     ('Relocatable Modules Dependant Upon','relocatable_modules_dependant_upon'),
                                     ('* Commands','star_commands'),
                                     ('Source','source'),
                                     ('System Variables','system_variables'),
                                     ('Territories','territories'),
                                     ('Utilities','utilities'),
                                     ('ZIP File','zip_file')
                                     ]
        
        self.fileTypeChars = [('0000','0'),
                              ('0001','1'),
                              ('0010','2'),
                              ('0011','3'),
                              ('0100','4'),
                              ('0101','5'),
                              ('0110','6'),
                              ('0111','7'),
                              ('1000','8'),
                              ('1001','9'),
                              ('1010','A'),
                              ('1011','B'),
                              ('1100','C'),
                              ('1101','D'),
                              ('1110','E'),
                              ('1111','F')
                             ]       

        self.baseUrlPattern = re.compile('(?i)<base\s+href="([^#"]+)"')
        self.externalLinkPattern = re.compile('((?:http|https|ftp|feed)://[^< ">]+)')
        self.internalLinkPattern = re.compile('(?i)href="([^#"]+)"')
        self.appAuthorPattern = re.compile('(?:_Author|AppAuthor):(.+)')
        self.appDirPattern = re.compile('^(?i)(?:\!Boot/Resources/)?(?:Apps/Network/)?(\!\w+)/$')
        self.appNameFromMessagesPattern = re.compile('(?:_TaskName|AppName):(.+)')
        self.appNamePattern = re.compile('(?i)About this program\s([\w ]+)\s')
        self.appPurposePattern = re.compile('(?:_Purpose|AppPurpose):(.+)')
        self.appVersionPattern = re.compile('(?:_Version|AppVersion):(.+)')
        self.appVerDatePattern = re.compile('(?i)(\d+\.\d+)\s+\((\d{2}[\- ](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[\- ](?:\d{2})?\d{2})\)')
        self.buildDependsPattern = re.compile('Build-Depends: (.+)')
        self.copyrightFromObeyPattern = re.compile('(?i)| \xa9 Copyright (.+?)\S')
        self.copyrightPattern = re.compile('(?i)\x0d(Copyright \xa9 [\w\s]+)\x0d')
        self.descriptionPattern = re.compile('Description: (.+)')
        self.fileTypePattern = re.compile('(?i)Set File\$Type_(\w\w\w) (\w+)')
        self.licencePattern = re.compile('(?i)This program is (Public Domain|Freeware|Careware)')
        self.maintainerPattern = re.compile('Maintainer: (.+)')
        self.moduleVersionPattern = re.compile('\t(\d+\.\d+)\s\(\d\d\s\w\w\w\s\d\d\d\d\)')
        self.otherPackagePattern = re.compile('([^ ]+) \((.+)\)')
        self.packageNamePattern = re.compile('Package: (.+)')
        self.packageVersionPattern = re.compile('Version: (.+)')
        self.priorityPattern = re.compile('Priority: (.+)')
        self.rmensurePattern = re.compile('(?i)RMEnsure (\w+) (\d+\.\d+)')
        self.minOsVerPattern = re.compile('(?i)RMEnsure\s+UtilityModule\s+(\d+\.\d+)')
        self.runTypePattern = re.compile('(?i)Set Alias\$@RunType_(\w\w\w)')
        self.sectionPattern = re.compile('Section: (.+)')
        self.sourcePattern = re.compile('Source: (.+)')
        self.sysVarPattern = re.compile('(?i)Set ([A-Za-z0-9]{3}\$(?:Dir|Path))')
        self.titlePattern = re.compile('<title>(.*?)</title>')
        self.utilityVersionPattern = re.compile('(\d+\.\d+\s\(\d\d\s\w\w\w\s\d\d\d\d\))')
        self.appVerFromTemplatesPattern = re.compile('\x0d(\d+\.\d+\s+\(\d\d-\w\w\w-\d\d\d?\d?\))\x0d')
        self.dotdotslashPattern = re.compile('(/\w+/\.\./)')
        
        self.path = os.path.dirname(os.path.abspath(__file__))
    #enddef
    
    def ascii_to_bin(self,char):
        ascii = ord(char)
        bin = []
        while (ascii > 0):
            if (ascii & 1) == 1:
                bin.append("1")
            else:
                bin.append("0")
            #endif
            ascii = ascii >> 1
        #endwhile
        bin.reverse()
        binary = "".join(bin)
        zerofix = (8 - len(binary)) * '0'
        return zerofix + binary
    #enddef    

    def remove_dead_links(self):
        searchCriteria = {}
        searchCriteria['url'] = re.compile('^/riscos/software')
        urls = self.riscosCollection.find(searchCriteria).distinct('url')
        for url in urls:
            osPath = self.path+url.replace('/',os.sep)
            osPath = osPath.replace(os.sep+'riscos'+os.sep+'riscos'+os.sep,os.sep+'riscos'+os.sep)
            if not os.path.exists(osPath):
                print "Removing "+url+"..."
                self.riscosCollection.remove({'url':url})
            #endif
        #endfor
    #enddef
    
    def scan_software_directories(self):
        for directoryName in ['softwareconfirmed','softwareunconfirmed']:
            print "Scanning '"+directoryName+"' directory has started..."
            self.scan_software_directory(self.path+os.sep+directoryName)
            print "Scanning '"+directoryName+"' directory has finished!"
        #endfor
    #enddef   
    
    def scan_software_directory(self, currentDir):
        objects = os.listdir(currentDir)
        for object in objects:
            objectPath = currentDir+os.sep+object
            if os.path.isdir(objectPath):
                self.scan_software_directory(objectPath)
            elif objectPath.lower().endswith('.zip'):
                restOfPath = objectPath.replace(self.path,"")
                url = '/riscos'+restOfPath.replace(os.sep,'/')
                count = self.riscosCollection.find({'url':url}).count()               
                if not count:
                    #print "Processing "+url+"..."
                    apps = self.analyse_zip_file(objectPath)
                    self.update_apps(url, apps)
                #endif
            #endif
        #endfor    
    #enddef
    
    def update_apps(self, url, apps):
        epoch = int(time.time())
        for [absolutes,appDate,appDir,appName,appVer,author,categories,copyright,description,dtpFormats,filetypesRead,filetypesSet,fonts,help,license,maintainer,minOsVers,monitorDefinitionFiles,packageName,packageSection,packageVersion,printerDefinitionFiles,priority,programmingLanguages,relocatableModules,relocatableModulesDependantUpon,source,territories,starCommands,systemVariables,toolboxRequired,utilities] in apps:
            existingDocument = ""
            if appDir:
                existingDocument = self.riscosCollection.find_one({'url':url,'application_directory':appDir})
            #endif
            if existingDocument:
                if url.__contains__('/softwareconfirmed/'):
                    existingDocument['zip_file'] = url
                #endif
                existingDocument['last_scanned'] = epoch
                if absolutes:
                    existingDocument['absolutes'] = absolutes
                #endif
                if appDate:
                    existingDocument['application_date'] = appDate
                #endif
                if appName and appName != 'ProgInfo':
                    existingDocument['application_name'] = appName
                #endif
                if appVer:
                    existingDocument['application_version'] = appVer
                #endif
                if author:
                    existingDocument['author'] = author
                #endif
                if categories:
                    existingDocument['categories'] = categories
                #endif
                if copyright:
                    existingDocument['copyright'] = copyright
                #endif
                if description:
                    existingDocument['description'] = description
                #endif
                if dtpFormats:
                    existingDocument['dtp_formats'] = dtpFormats
                #endif
                if filetypesRead:
                    existingDocument['filetypes_read'] = filetypesRead
                #endif
                if filetypesSet:
                    existingDocument['filetypes_set'] = filetypesSet
                #endif
                if fonts:
                    existingDocument['fonts'] = fonts
                #endif                
                if help:
                    try:
                        existingDocument['help'] = help
                    except:
                        True
                #endif
                if license:
                    existingDocument['license'] = license
                #endif
                if maintainer:
                    existingDocument['maintainer'] = maintainer
                #endif
                if minOsVers:
                    existingDocument['minimum_riscos_versions'] = minOsVers
                #endif
                if monitorDefinitionFiles:
                    existingDocument['monitor_definition_files'] = monitorDefinitionFiles
                #endif
                if packageName:
                    existingDocument['package_name'] = packageName
                #endif
                if packageSection:
                    existingDocument['package_section'] = packageSection
                #endif
                if packageVersion:
                    existingDocument['package_version'] = packageVersion
                #endif
                if printerDefinitionFiles:
                    existingDocument['printer_definition_files'] = printerDefinitionFiles
                #endif
                if priority:
                    existingDocument['priority'] = priority
                #endif
                if programmingLanguages:
                    existingDocument['programming_languages'] = list(set(programmingLanguages))
                #endif
                if relocatableModules:
                    existingDocument['relocatable_modules'] = relocatableModules
                #endif
                if relocatableModulesDependantUpon:
                    existingDocument['relocatable_modules_dependant_upon'] = relocatableModulesDependantUpon
                #endif
                if source:
                    existingDocument['source'] = source
                #endif          
                if territories:
                    existingDocument['territories'] = list(set(territories))
                #endif
                if starCommands:
                    existingDocument['star_commands'] = starCommands
                #endif
                if systemVariables:
                    existingDocument['system_variables'] = systemVariables
                #endif
                if toolboxRequired:
                    existingDocument['toolbox_required'] = toolboxRequired
                #endif
                if utilities:
                    existingDocument['utilities'] = utilities
                #endif
                try:
                    self.riscosCollection.save(existingDocument)
                except:
                    True
            else:
                subDocument = {}
                subDocument['url'] = url
                if url.__contains__('/softwareconfirmed/'):
                    subDocument['zip_file'] = url
                #endif
                subDocument['last_scanned'] = epoch
                if absolutes:
                    subDocument['absolutes'] = absolutes
                #endif
                if appDate:
                    subDocument['application_date'] = appDate
                #endif
                if appDir:
                    subDocument['application_directory'] = appDir
                #endif
                if appName and appName != 'ProgInfo':
                    subDocument['application_name'] = appName
                #endif
                if appVer:
                    subDocument['application_version'] = appVer
                #endif
                if author:
                    subDocument['author'] = author
                #endif
                if categories:
                    subDocument['categories'] = categories
                #endif
                if copyright:
                    subDocument['copyright'] = copyright
                #endif
                if description:
                    subDocument['description'] = description
                #endif
                if dtpFormats:
                    subDocument['dtp_formats'] = dtpFormats
                #endif
                if filetypesRead:
                    subDocument['filetypes_read'] = filetypesRead
                #endif
                if filetypesSet:
                    subDocument['filetypes_set'] = filetypesSet
                #endif
                if fonts:
                    subDocument['fonts'] = fonts
                #endif                
                if help:
                    try:
                        subDocument['help'] = help
                    except:
                        True
                #endif
                if license:
                    subDocument['license'] = license
                #endif
                if maintainer:
                    subDocument['maintainer'] = maintainer
                #endif
                if minOsVers:
                    subDocument['minimum_riscos_versions'] = minOsVers
                #endif
                if monitorDefinitionFiles:
                    subDocument['monitor_definition_files'] = monitorDefinitionFiles
                #endif
                if packageName:
                    subDocument['package_name'] = packageName
                #endif
                if packageSection:
                    subDocument['package_section'] = packageSection
                #endif
                if packageVersion:
                    subDocument['package_version'] = packageVersion
                #endif
                if printerDefinitionFiles:
                    subDocument['printer_definition_files'] = printerDefinitionFiles
                #endif
                if priority:
                    subDocument['priority'] = priority
                #endif
                if programmingLanguages:
                    subDocument['programming_languages'] = list(set(programmingLanguages))
                #endif
                if relocatableModules:
                    subDocument['relocatable_modules'] = relocatableModules
                #endif
                if relocatableModulesDependantUpon:
                    subDocument['relocatable_modules_dependant_upon'] = relocatableModulesDependantUpon
                #endif
                if source:
                    subDocument['source'] = source
                #endif          
                if territories:
                    subDocument['territories'] = list(set(territories))
                #endif
                if starCommands:
                    subDocument['star_commands'] = list(set(starCommands))
                #endif          
                if systemVariables:
                    subDocument['system_variables'] = list(set(systemVariables))
                #endif
                if toolboxRequired:
                    subDocument['toolbox_required'] = toolboxRequired
                #endif
                if utilities:
                    subDocument['utilities'] = utilities
                #endif
                try:
                    self.riscosCollection.insert(subDocument)
                except:
                    True
            #endif
        #endfor
    #enddef   
    
    def analyse_zip_file(self, filepath):
        apps = []
        if filepath:
            if os.path.exists(filepath):
                if zipfile.is_zipfile(filepath):
                    z = zipfile.ZipFile(filepath, mode="r")
                    objects = z.namelist()
                    appDirs = []
                    for object in objects:
                    
                        results = self.appDirPattern.findall(object)
                        
                        if results != []:
                            for result in results:
                                appDirs.append(result)
                            #endfor
                        #endf
                    #endfor
                    for appDir in appDirs:
                    
                        absolutes = []
                        app = []
                        appDate = ""
                        appName = ""
                        appVer = ""
                        author = ""
                        categories = []
                        copyright = ""
                        description = ""
                        dtpFormats = []
                        filetypesSet = []
                        filetypesRead = []
                        fonts = []
                        help = ""
                        license = ""
                        maintainer = ""
                        minOsVers = []
                        monitorDefinitionFiles = []
                        packageName = ""
                        packageSection = ""
                        packageVersion = ""
                        printerDefinitionFiles = []
                        priority = ""
                        programmingLanguages = []
                        relocatableModules = []
                        relocatableModulesDependantUpon = []
                        source = ""
                        territories = []
                        starCommands = []
                        systemVariables = []
                        toolboxRequired = ""
                        utilities = []           
                        templatesFiles = []                      
                    
                        for object in objects:
                            if object.__contains__('Apps/') and object.endswith('/'+appDir):
                                categoryPattern = re.compile('Apps/(\w+)/'+appDir)
                                results = categoryPattern.findall(object)
                                if results:
                                    if results[0] in ["Administration","Archive","Audio","Chat","Communication","Database","Demo","Desktop","Development","Device","Disc","Document","File","Education","Emulation","Font","Games","Graphics","Library","Mail","Mathematics","Miscellaneous","Network","Presentation","Printing","Spreadsheet","System","Text","Video","Web"]:
                                        if not results[0] in categories:
                                            categories = results[0]
                                        #endif
                                    #endif
                                #endif
                            #endif
                        #endfor
                    
                        for object in objects:
                        
                            if not object.lower().startswith(appDir.lower()):
                                continue
                            #endif
                        
                            zipinfo = z.getinfo(object)
                            identifiedFileType = ['','','']

                            try:
                                twoFileTypeChars = zipinfo.FileHeader()[len(zipinfo.FileHeader())-15:len(zipinfo.FileHeader())-13]
                                binary = self.ascii_to_bin(twoFileTypeChars[1])
                                for fileTypeChar in self.fileTypeChars:
                                    if binary[:4] == fileTypeChar[0]:
                                        identifiedFileType[0] = fileTypeChar[1]
                                    #endif
                                #endfor
                                binary = self.ascii_to_bin(twoFileTypeChars[0])
                                for fileTypeChar in self.fileTypeChars:
                                    if binary[:4] == fileTypeChar[0]:
                                        identifiedFileType[1] = fileTypeChar[1]
                                    #endif
                                    if binary[4:] == fileTypeChar[0]:
                                        identifiedFileType[2] = fileTypeChar[1]
                                    #endif
                                #endfor
                            except:
                                True

                            if identifiedFileType == ['1','0','2']:
                                if not 'Perl' in programmingLanguages:
                                    programmingLanguages.append('Perl')
                                #endif
                            elif identifiedFileType == ['1','8','A']:
                                if not 'PHP' in programmingLanguages:
                                    programmingLanguages.append('PHP')
                                #endif
                            elif identifiedFileType == ['3','D','6']:
                                # StrongHelpFile
                                True
                            elif identifiedFileType == ['A','D','F']:
                                # PDFFile
                                True
                            elif identifiedFileType == ['A','E','4']:
                                if not 'Java' in programmingLanguages:
                                    programmingLanguages.append('Java')
                                #endif
                            elif identifiedFileType == ['A','E','5']:
                                if not 'Python' in programmingLanguages:
                                    programmingLanguages.append('Python')
                                #endif
                            elif identifiedFileType == ['A','E','6']:
                                if not 'Microsoft Word' in dtpFormats:
                                    dtpFormats.append('Microsoft Word')
                                #endif
                            elif identifiedFileType == ['A','E','7']:
                                # ARMovieFile
                                True
                            elif identifiedFileType == ['A','F','F']:
                                # DrawFile
                                True
                            elif identifiedFileType == ['B','C','5']:
                                if not 'Impression' in dtpFormats:
                                    dtpFormats.append('Impression')
                                #endif
                            elif identifiedFileType == ['B','2','7']:
                                if not 'Ovation' in dtpFormats:
                                    dtpFormats.append('Ovation')
                                #endif
                            elif identifiedFileType == ['C','3','2']:
                                if not 'RTF' in dtpFormats:
                                    dtpFormats.append('RTF')
                                #endif
                            elif identifiedFileType == ['D','D','C']:
                                # ArchiveFile
                                True
                            elif identifiedFileType == ['D','1','C']:
                                # ArcScanFile
                                True
                            elif identifiedFileType == ['F','A','E']:
                                toolboxRequired = True
                            elif identifiedFileType == ['F','A','F']:
                                if not 'HTMLFile' in dtpFormats:
                                    dtpFormats.append('HTMLFile')
                                #endif
                            elif identifiedFileType == ['F','D','7']:
                                # TaskObeyFile
                                True
                            elif identifiedFileType == ['F','E','B']:
                                # ObeyFile
                                True
                            elif identifiedFileType == ['F','E','5']:
                                # EPROMFile
                                True
                            elif identifiedFileType == ['F','E','C']:
                                templatesFiles.append(object)
                            elif identifiedFileType == ['F','F','2']:
                                # CMOSRAMFile
                                True
                            elif identifiedFileType == ['F','F','5']:
                                if not 'PostscriptFile' in dtpFormats:
                                    dtpFormats.append('PostscriptFile')
                                #endif
                            elif identifiedFileType == ['F','F','6']:
                                modifiedObject = object.replace('/','.')
                                if not modifiedObject in fonts:
                                    fonts.append(modifiedObject)
                                #endif
                            elif identifiedFileType == ['F','F','8']:
                                if object.lower().__contains__('!runimage'):
                                    if not 'Absolute' in programmingLanguages:
                                        programmingLanguages.append('Absolute')
                                    #endif
                                else:
                                    if not object in absolutes:
                                        if not object in absolutes:
                                            if not object.lower().endswith('!runimage'):
                                                absolutes.append(object.replace('/','.'))
                                            #endif
                                        #endif
                                    #endif
                                #endif
                            elif identifiedFileType == ['F','F','9']:
                                # SpriteFile
                                True
                            elif identifiedFileType == ['F','F','A']:
                                components = object.split('/')
                                moduleName = components[len(components)-1]
                                try:
                                    contents = z.read(object)
                                    results = self.moduleVersionPattern.findall(contents)
                                    if results != []:
                                        relocatableModules.append({'name':moduleName,'version':results[0]})
                                    else:
                                        relocatableModules.append({'name':moduleName})
                                    #endif
                                except:
                                    True
                            elif identifiedFileType == ['F','F','B']:
                                if object.lower().__contains__('!runimage'):
                                    if not 'BBC BASIC' in programmingLanguages:
                                        programmingLanguages.append('BBC BASIC')
                                    #endif
                                #endif
                            elif identifiedFileType == ['F','F','C']:
                                encodedUtility = ""
                                contents = z.read(object)
                                results = self.utilityVersionPattern.findall(contents)
                                if object.__contains__('/'):
                                    components = object.split('/')
                                    utility = components[len(components)-1]
                                    encodedUtility = utility.replace('/','.')
                                else:
                                    try:
                                        encodedUtility = object
                                    except:
                                        True                                
                                #endif
                                if encodedUtility:
                                    if results != []:
                                        if not encodedUtility+' '+results[0] in utilities:
                                            utilities.append(encodedUtility+' '+results[0])
                                        #endif
                                    else:
                                        if not encodedUtility in utilities:
                                            utilities.append(encodedUtility)
                                        #endif
                                    #endif
                                    # syntaxPattern = re.compile('\x00Syntax:\s([^\s])\s(.+?)\x00')
                                    # results = syntaxPattern.findall(contents)
                                    # if results != []:
                                    #      utilitySyntax = results[1]
                                    # #endif
                                #endif
                            elif identifiedFileType == ['F','F','F']:
                                if object.lower() == 'riscpkg/control':
                                    contents = z.read(object)
                                    results = self.packageNamePattern.findall(contents)
                                    if results != []:
                                        packageName = results[0]
                                        results = self.packageVersionPattern.findall(contents)
                                        if results != []:
                                            packageVersion = results[0]                                    
                                        #endif
                                    #endif
                                    if packageName != '':
                                        results = self.priorityPattern.findall(contents)
                                        if results != []:
                                            priority = results[0]
                                        #endif
                                    
                                        results = self.sectionPattern.findall(contents)
                                        if results != []:
                                            packageSection = results[0]
                                        #endif
                                        results = self.maintainerPattern.findall(contents)
                                        if results != []:
                                            maintainer = results[0]
                                        #endif
                                        results = self.sourcePattern.findall(contents)
                                        if results != []:
                                            source = results[0]
                                        #endif
                                    
                                        results = self.buildDependsPattern.findall(contents)
                                        if results != []:
                                            otherPackages = results[0].split(',')
                                            for otherPackage in otherPackages:
                                                otherPackage = otherPackage.strip()
                                                otherPackageResults = self.otherPackagePattern.findall(otherPackage)
                                                if otherPackageResults != []:
                                                    packagesDependantUpon.append(otherPackageResults[0][0]+' '+otherPackageResults[0][1])
                                                else:
                                                    packagesDependantUpon.append(otherPackage)
                                                #endif
                                            #endfor
                                        #endif
                                    
                                        results = self.descriptionPattern.findall(contents)
                                        if results != []:
                                            description = results[0]
                                        #endif
                                    #endif
                                else:
                                    if object.lower().endswith('/messages'):
                                        if object.lower().endswith(appDir.lower()+'/messages') or object.lower().endswith(appDir.lower()+'/resources/en/messages') or object.lower().__contains__('/uk/'):
                                            if not 'English' in territories:
                                                territories.append('English')
                                            #endif
                                        elif object.lower().endswith(appDir.lower()+'/resources/nl/messages') or object.lower().__contains__('/netherland/'):
                                            if not 'Dutch' in territories:
                                                territories.append('Dutch')
                                            #endif
                                        elif object.lower().endswith(appDir.lower()+'/resources/de/messages') or object.lower().__contains__('/germany/'):
                                            if not 'German' in territories:
                                                territories.append('German')
                                            #endif
                                        elif object.lower().endswith(appDir.lower()+'/resources/fr/messages') or object.lower().__contains__('/france/'):
                                            if not 'French' in territories:
                                                territories.append('French')
                                            #endif
                                        elif object.lower().endswith(appDir.lower()+'/resources/it/messages'):
                                            if not 'Italian' in territories:
                                                territories.append('Italian')
                                            #endif
                                        #endif
                                    else:
                                        try:
                                            contents = z.read(object)
                                            if contents.startswith('# Modefile written by !MakeModes') or contents.startswith('# Monitor description file'):
                                                if not object in monitorDefinitionFiles:
                                                    monitorDefinitionFiles.append(object.replace('/','.'))
                                                #endif
                                            #endif
                                        except:
                                            True
                                    #endif
                                #endif
                            #endif

                            if object.lower().startswith(appDir.lower()+'/c/') or (object.lower().startswith(appDir.lower()) and object.lower().__contains__('/c/')) or object.lower().startswith(appDir.lower()+'/h/') or (object.lower().startswith(appDir.lower()) and object.lower().__contains__('/h/')):
                                sourceCode = True
                                if not 'C/C++' in programmingLanguages:
                                    programmingLanguages.append('C/C++')
                                #endif

                            elif object in templatesFiles:
                                try:
                                    contents = z.read(object)
                                except:
                                    True
                                results = self.appNamePattern.findall(contents)
                                if results != []:
                                    appName = results[0]
                                #endif
                                
                                results = self.copyrightPattern.findall(contents)
                                if results != []:
                                    copyright = results[0]
                                #endif
                                results = self.appVerFromTemplatesPattern.findall(contents)
                                if results != []:
                                    subResults = self.appVerDatePattern.findall(results[0])
                                    if subResults:
                                        if subResults[0][0] != '0.00':
                                            appVer = subResults[0][0]
                                        #endif
                                        if not subResults[0][1] in ['01-Jan-00','01 Jan 00','01-Jan-1900','01 Jan 1900']:
                                            appDate = subResults[0][1].replace(' ','-')
                                            if len(appDate) == 9:
                                                if int(appDate[7:]) >= 87:
                                                    appDate = appDate[:7]+'19'+appDate[7:]
                                                else:
                                                    appDate = appDate[:7]+'20'+appDate[7:]
                                                #endif
                                            #endif
                                        #endif
                                    #endif
                                #endif

                            elif object.lower() == appDir.lower()+'/!help':
                                try:
                                    contents = z.read(object)
                                    contents = contents.strip()
                                    contents = contents.replace('\n',' ')
                                    while contents.__contains__('  '):
                                        contents = contents.replace('  ',' ')
                                    #endwhile
                                
                                    help = contents

                                    results = self.licencePattern.findall(contents)
                                    if results != []:
                                        license = results[0]
                                    #endif
                                except:
                                    True
                            elif object.lower() == appDir.lower()+'/messages' or object.lower() == appDir.lower()+'/resources/1/messages':

                                contents = z.read(object)

                                results = self.appNameFromMessagesPattern.findall(contents)
                                if results != []:
                                    appName = result[0]
                                #endif

                                results = self.appPurposePattern.findall(contents)
                                if results != []:
                                    purpose = results[0]
                                #endif

                                results = self.appAuthorPattern.findall(contents)

                                if results != []:
                                    author = results[0]
                                #endif

                                results = self.appVersionPattern.findall(contents)
                                if results != []:

                                    subResults = self.appVerDatePattern.findall(results[0])
                                    if subResults:
                                        if subResults[0][0] != '0.00':
                                            appVer = subResults[0][0]
                                        #endif
                                        if not subResults[0][1] in ['01-Jan-00','01 Jan 00','01-Jan-1900','01 Jan 1900']:
                                            appDate = subResults[0][1].replace(' ','-')
                                            if len(appDate) == 9:
                                                if int(appDate[7:]) >= 87:
                                                    appDate = appDate[:7]+'19'+appDate[7:]
                                                else:
                                                    appDate = appDate[:7]+'20'+appDate[7:]
                                                #endif
                                            #endif
                                        #endif
                                    #endif
                                #endif

                            elif object.lower() == appDir.lower()+'/!boot' or object.lower() == '!boot/resources/'+appDir.lower()+'/!boot' or object.lower() == appDir.lower()+'/!run' or object.lower() == '!boot/resources/'+appDir.lower()+'/!run':
                                try:
                                    contents = z.read(object)
                                except:
                                    contents = ""
                                    
                                results = self.copyrightFromObeyPattern.findall(contents)
                                
                                if results != []:
                                    copyright = results[0]
                                #endif

                                results = self.minOsVerPattern.findall(contents)
                                if results != []:
                                    if '3.70' in results:
                                        minOsVers.append(3.70)
                                    elif '3.60' in results:
                                        minOsVers.append(3.60)
                                    elif '3.50' in results:
                                        minOsVers.append(3.50)
                                    elif '3.11' in results:
                                        minOsVers.append(3.11)
                                    elif '3.10' in results:
                                        minOsVers.append(3.10)
                                    elif '3.00' in results or '3.0' in results:
                                        minOsVers.append(3.00)
                                    elif '2.00' in results:
                                        minOsVers.append(2.00)
                                    #endif
                                    
                                    if '6.20' in results:
                                        minOsVers.append(6.20)
                                    elif '6.00' in results:
                                        minOsVers.append(6.00)
                                    elif '4.00' in results:
                                        minOsVers.append(4.00)
                                    #endif
                    
                                    if '5.00' in results:
                                        minOsVers.append(5.00)
                                    #endif
                                #endif

                                results = self.runTypePattern.findall(contents)
                                if results != []:
                                    for result in results:
                                        if not result in filetypesRead:
                                            filetypesRead.append(result)
                                        #endif
                                    #endfor
                                #endif

                                results = self.fileTypePattern.findall(contents)
                                if results != []:
                                    for result in results:
                                        if not result[0]+' '+result[1] in filetypesSet:
                                            filetypesSet.append(result[0]+' '+result[1])
                                        #endif
                                    #endfor
                                #endif

                                results = self.sysVarPattern.findall(contents)
                                if results != []:
                                    for result in results:
                                        if not result in systemVariables:
                                            systemVariables.append(result)
                                        #endif
                                    #endfor
                                #endif

                                results = self.rmensurePattern.findall(contents)
                                if results != []:
                                    for result in results:
                                        if not {'name':result[0],'version':result[1]} in relocatableModulesDependantUpon:
                                            relocatableModulesDependantUpon.append({'name':result[0],'version':result[1]})
                                        #endif
                                    #endfor
                                #endif
                            #endif
                        #endfor
                        for component in [absolutes,appDate,appDir,appName,appVer,author,categories,copyright,description,dtpFormats,filetypesRead,filetypesSet,fonts,help,license,maintainer,minOsVers,monitorDefinitionFiles,packageName,packageSection,packageVersion,printerDefinitionFiles,priority,programmingLanguages,relocatableModules,relocatableModulesDependantUpon,source,territories,starCommands,systemVariables,toolboxRequired,utilities]:
                            app.append(component)
                        #endfor
                        apps.append(app)
                    #endfor
                    z.close()
                #endif
            #endif
        #endif
        return apps
    #enddef
#endclass

if __name__ == '__main__':
    riscossoftware = riscossoftware()
    riscossoftware.remove_dead_links()
    riscossoftware.scan_software_directories()
