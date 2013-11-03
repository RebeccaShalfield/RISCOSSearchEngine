# Spidering For The RISC OS Search Engine
# Developed by Rebecca Shalfield for The RISC OS Community
# Copyright (c) Rebecca Shalfield 2002-2013

import hashlib, httplib, re, os, pymongo, socket, sys, time, urllib, urllib2, urlparse, zipfile
from pymongo import Connection
from bson import ObjectId
from random import randint
from urllib2 import HTTPError
from ssl import SSLError
from lxml import etree

class riscosspider:

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
        
        # Connect to 'urls' collection
        self.urlsCollection = db['urls']
        
        # Connect to 'rejects' collection
        self.rejectsCollection = db['rejects']
        
        # Connect to 'reserves' collection
        self.reservesCollection = db['reserves']
    
        self.housekeepingTasksLastRan = []
    
        self.mirror = 'www.shalfield.com/riscos'
        self.mirrors = ['84.92.157.78/riscos','www.shalfield.com/riscos','192.168.88.1:8081/riscos']
    
        self.searchableAttributes = [
                                     ('Absolutes','absolutes'),
                                     ('Application Date','application_date'),
                                     ('Application Directory','application_directory'),
                                     ('Application Name','application_name'),
                                     ('Application Version','application_version'),
                                     ('ARC File','arc_file'),
                                     ('Author','author'),
                                     ('Book','book'),
                                     ('Categories','categories'),
                                     ('Computer','computer'),
                                     ('Copyright','copyright'),
                                     ('Description','description'),
                                     ('Developer','developer'),
                                     ('DTP Formats','dtp_formats'),
                                     ('Event','event',),
                                     ('Filetypes Read','filetypes_read'),
                                     ('Filetypes Set','filetypes_set'),
                                     ('Fonts','fonts'),
                                     ('Forum','forum'),
                                     ('Glossary Term','glossary_term'),
                                     ('Glossary Definition','glossary_definition'),
                                     ('Help','help'),
                                     ('Identifier','identifier'),
                                     ('Last Modified','last_modified'),
                                     ('License','license'),
                                     ('Magazine','magazine'),
                                     ('Maintainer','maintainer'),
                                     ('Minimum RISC OS Versions','minimum_riscos_versions'),
                                     ('Monitor Definition Files','monitor_definition_files'),
                                     ('Package Name','package_name'),
                                     ('Package Section','package_section'),
                                     ('Package Version','package_version'),
                                     ('Page Title','page_title'),
                                     ('Podule','podule'),
                                     ('Portable Document Format File','pdf_file'),
                                     ('Price','price'),
                                     ('Printer Definition Files','printer_definition_files'),
                                     ('Priority','priority'),
                                     ('Programming Languages','programming_languages'),
                                     ('Provider','provider'),
                                     ('Publisher','publisher'),
                                     ('Purpose','purpose'),
                                     ('Relocatable Modules','relocatable_modules'),
                                     ('Relocatable Modules Dependant Upon','relocatable_modules_dependant_upon'),
                                     ('RSS Feed','rss_feed'),
                                     ('RSS Feed Item Date','rss_feed_item_date'),
                                     ('RSS Feed Item Description','rss_feed_item_description'),
                                     ('RSS Feed Item Link','rss_feed_item_link'),
                                     ('RSS Feed Item Title','rss_feed_item_title'),
                                     ('* Commands','star_commands'),
                                     ('Source','source'),
                                     ('Spark File','spark_file'),
                                     ('System Variables','system_variables'),
                                     ('Territories','territories'),
                                     ('User Group','user_group'),
                                     ('Utilities','utilities'),
                                     #('Video','video'),
                                     ('ZIP File','zip_file')
                                     ]
        
        if self.riscosCollection.find({}).count() == 0 and self.urlsCollection.find({}).count() == 0:
            document = {}
            document['last_scanned'] = 0
            epoch = int(time.time())
            document['next_scan'] = epoch
            document['seed'] = True
            for url in ['http://www.riscosopen.org/']:
                document['url'] = url
                self.urlsCollection.insert(document)
                print "Inserting into urls: "+document['url']
            #endfor
        #endif       
        
        self.periodDay = 86400
        self.periodWeek = 604800
        self.periodMonth = 2419200
        self.periodYear = 31536000
        
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
        self.metaRobotsPattern = re.compile('<meta\s+name="robots"\s+content="(.*)">')
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
        self.titlePattern = re.compile('<title>\s*(.*?)\s*</title>')
        self.utilitySyntaxPattern = re.compile('\x00Syntax:\s([^\s])\s(.+?)\x00')
        self.utilityVersionPattern = re.compile('(\d+\.\d+\s\(\d\d\s\w\w\w\s\d\d\d\d\))')
        self.appVerFromTemplatesPattern = re.compile('\x0d(\d+\.\d+\s+\(\d\d-\w\w\w-\d\d\d?\d?\))\x0d')
        self.dotdotslashPattern = re.compile('(/\w+/\.\./)')
        self.archivedUrlPattern = re.compile('http://web\.archive\.org/.*(http://.*)$')
        self.archivedDatePattern = re.compile('http://web\.archive\.org/web/(\d{14})/http://.*$')
        self.youTubeEmbedPattern = re.compile('''<textarea class="yt-uix-form-input-textarea share-embed-code" onkeydown="if \(\(event.ctrlKey \|\| event.metaKey\) &amp;&amp; event.keyCode == 67\) \{ yt.tracking.track\('embedCodeCopied'\); }">(.+?)</textarea>''')

        self.blacklist = ['edit.yahoo.com',
                          'validator.w3.org'
                         ]
        
        self.suspension = ['yahooshopping.pgpartner.com',
                           'shopping.yahoo.com'
                          ]
        
        self.usualDomains = ['forum.acorn.de',
                             'www.apdl.co.uk',
                             'www.chriswhy.co.uk',
                             'www.drobe.co.uk',
                             'www.ebay.co.uk',
                             'www.iconbar.co.uk',
                             'www.myriscos.co.uk',
                             'www.riscosopen.org',
                             'stardot.org.uk',
                             'www.thedownloadplanet.com',
                             'www.archive.org'
                            ]
        
        self.lastSuccessfulInternetConnection = 0
        
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

    def continuous(self):
        print "Spidering has started..."
        while True:
            hour = time.localtime()[3]
            if (hour >= 6 and hour <= 22):
                print "Performing housekeeping..."
                self.housekeeping()
            #endif           
            print "Spidering is running..."
            latestMessage = self.spider()
            print latestMessage            
        #endwhile
        print "Spidering has finished!"
    #enddef

    def normalise_url(self, url):
        pattern = re.compile('(/[^/\.]+/\.\.)')
        while url.__contains__('/..'):
            results = pattern.findall(url)
            if results:
                url = url.replace(results[0],'')
            else:
                break
            #endif
        #endwhile
        return url
    #enddef   
    
    def blacklisted_document(self, document):
        url = document['url']
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            if netloc in self.blacklist:
                for blacklistedDocument in self.urlsCollection.find({'domain':netloc,'_id':{'$ne':ObjectId(document['_id'])}}):
                    print 'Removing Blacklisted URL '+blacklistedDocument['url']+'...'
                    self.urlsCollection.remove({'_id':ObjectId(blacklistedDocument['_id'])})
                #endfor
                return True
            elif netloc+'/'+path in self.blacklist:
                searchCriteria = {}
                searchCriteria['url'] = re.compile(netloc+'/'+path)
                searchCriteria['_id'] = {'$ne':ObjectId(document['_id'])}
                for blacklistedDocument in self.urlsCollection.find(searchCriteria):
                    print 'Removing Blacklisted URL '+blacklistedDocument['url']+'...'
                    self.urlsCollection.remove({'_id':ObjectId(blacklistedDocument['_id'])})
                #endfor            
                return True
            else:
                return False
            #endif            
        except ValueError:
            # Possibly due to a IPv6 URL
            False
        #endtryexcept    
    #enddef    
    
    def blacklisted_url(self, url):
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            if netloc in self.blacklist or netloc+'/'+path in self.blacklist:
                return True
            else:
                return False
            #endif            
        except ValueError:
            # Possibly due to a IPv6 URL
            False
        #endtryexcept    
    #enddef
    
    def suspended_url(self, url):
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            if netloc in self.suspension or netloc+'/'+path in self.suspension:
                return True
            else:
                return False
            #endif            
        except ValueError:
            # Possibly due to a IPv6 URL
            False
        #endtryexcept    
    #enddef

    def suspended_document(self, document):
        url = document['url']
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            if netloc in self.suspension:
                for suspendedDocument in self.urlsCollection.find({'domain':netloc,'_id':{'$ne':ObjectId(document['_id'])}}):
                    print 'Moving Suspended to Reserves '+suspendedDocument['url']+'...'
                    newDocument = {}
                    newDocument['url'] = suspendedDocument['url']
                    self.reservesCollection.insert(newDocument)
                    print "Inserting into reserves: "+newDocument['url']
                    print 'Moving suspended URL '+suspendedDocument['url']+'...'
                    self.urlsCollection.remove({'_id':ObjectId(suspendedDocument['_id'])})
                #endfor
                return True
            elif netloc+'/'+path in self.suspension:
                searchCriteria = {}
                searchCriteria['url'] = re.compile(netloc+'/'+path)
                searchCriteria['_id'] = {'$ne':ObjectId(document['_id'])}
                for suspendedDocument in self.urlsCollection.find(searchCriteria):
                    print 'Moving Suspended to Reserves '+suspendedDocument['url']+'...'
                    newDocument = {}
                    newDocument['url'] = suspendedDocument['url']
                    self.reservesCollection.insert(newDocument)
                    print "Inserting into reserves: "+newDocument['url']
                    print 'Moving suspended URL '+suspendedDocument['url']+'...'
                    self.urlsCollection.remove({'_id':ObjectId(suspendedDocument['_id'])})
                #endfor                
                return True
            else:
                return False
            #endif            
        except ValueError:
            # Possibly due to a IPv6 URL
            False
        #endtryexcept    
    #enddef

    def usual_domain(self, url):      
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            if netloc in self.usualDomains:
                return True
            else:
                return False
            #endif            
        except ValueError:
            # Possibly due to a IPv6 URL
            False
        #endtryexcept
    #enddef
    
    def valid_hyperlink_filetype(self, url):
        validHyperlinkFiletype = True
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            for extension in ['.css','.gif','.dll','.dtd','.js','.jpeg','.jpg','.ico','.png','.src']:
                if path.lower().endswith(extension):
                    validHyperlinkFiletype = False
                    break               
                #endif
            #endfor
            if url.lower().startswith('mailto:'):
                validHyperlinkFiletype = False
            #endif
        except:
            True
        return validHyperlinkFiletype
    #enddef
      
    def remove_riscos_duplicates(self):
        try:
            for document in self.riscosCollection.find({}):
                searchCriteria = {}
                for key in document.keys():
                    if not key in ['last_scanned','next_scan','_id']:
                        searchCriteria[key] = document[key]
                    #endif                
                #endfor
                count = self.riscosCollection.find(searchCriteria).count()
                if count > 1:
                    print "Error: Identical riscos Documents Discovered..."
                    print ""
                    for identicalDocument in self.riscosCollection.find(searchCriteria):
                        print identicalDocument
                        print ""
                    #endfor
                    print "Removing from riscos: "+document['url']
                    self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                    break
                #endif
            #endfor
        except:
            True
    #enddef
    
    def remove_urls_duplicates(self):
        try:
            for document in self.urlsCollection.find({'url':{'$ne':''}}):
                count = self.urlsCollection.find({'url':document['url']}).count()
                if count > 1:
                    print "Removing duplicate from urls: "+document['url']
                    self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                    break
                #endif
            #endfor
        except:
            True
    #enddef 
    
    def identify_superseded_applications(self):
        for document in self.riscosCollection.find({'application_directory':{'$ne':''},'application_version':{'$ne':''}}):
            try:
                selectedVersion = float(document['application_version'])
                highestVersion = selectedVersion
                otherVersions = self.riscosCollection.find({'application_directory':document['application_directory'],'application_version':{'$ne':['',document['application_version']]}}).distinct('application_version')
                for otherVersion in otherVersions:
                    try:
                        if float(otherVersion) > highestVersion:
                            highestVersion = float(otherVersion)
                        #endif
                    except:
                        True
                #endfor
                if highestVersion > selectedVersion:
                    for otherDocument in self.riscosCollection.find({'application_directory':document['application_directory'],'application_version':str(highestVersion)}):
                        if float(otherDocument['application_version']) > float(document['application_version']):
                            document['superseded_by'] = otherDocument['_id']
                            self.riscosCollection.save(document)
                            break
                        #endif
                    #endfor
                #endif
            except:
                True
        #endfor
    #enddef
    
    def unlink_previously_superseded_applications(self):
        for document in self.riscosCollection.find({'superseded_by':{'$ne':''}}):
            if document.has_key('superseded_by') and document['superseded_by']:
                count = self.riscosCollection.find({'_id':ObjectId(document['superseded_by'])}).count()
                if not count:
                    del document['superseded_by']
                    self.riscosCollection.save(document)
                #endif
            #endif
        #endfor
    #enddef
    
    def url_in_riscos(self, url):
        if self.riscosCollection.find({'url':url}).count():
            return True
        else:
            return False
        #endif
    #enddef
    
    def url_in_urls(self, url):
        if self.urlsCollection.find({'url':url}).count():
            return True
        else:
            return False
        #endif
    #enddef
    
    def url_in_rejects(self, url):
        if self.rejectsCollection.find({'url':url}).count():
            return True
        else:
            return False
        #endif
    #enddef
    
    def url_in_reserves(self, url):
        if self.reservesCollection.find({'url':url}).count():
            return True
        else:
            return False
        #endif
    #enddef
    
    def housekeeping(self):
        noOfTasks = 16
        if not self.housekeepingTasksLastRan:
            for i in range(noOfTasks):
                self.housekeepingTasksLastRan.append(0)
            #endfor
        #endif
        epoch = int(time.time())
        selection = randint(0,noOfTasks-1)
        
        if self.housekeepingTasksLastRan[selection] >= epoch - self.periodDay:
            return
        #endif
        
        if selection == 0:
            print str(selection)+": Batch feed-in URLs from external file"
            path = self.path
            if os.path.exists(path+os.sep+'BatchUrlFeed.txt'):
                ip = open(path+os.sep+'BatchUrlFeed.txt','r')
                lines = ip.readlines()
                ip.close()
                if lines:
                    for line in lines:
                        if not self.url_in_riscos(line) and not self.url_in_urls(line) and not self.url_in_rejects(line) and not self.url_in_reserves(line) and not self.suspended_url(line) and not self.blacklisted_url(line):
                            newDocument = {}
                            newDocument['url'] = line
                            if line.lower().endswith('.zip') or line.lower().__contains__('.zip?'):
                                newDocument['zip_file'] = line
                                newDocument['last_scanned'] = 0
                            else:
                                newDocument['last_scanned'] = 1
                            #endif
                            newDocument['next_scan'] = epoch
                            self.urlsCollection.insert(newDocument)
                            print "Inserting into urls: "+newDocument['url']
                        #endif
                    #endfor
                    op = open(path+os.sep+'BatchUrlFeed.txt','w')
                    op.close()
                #endif                
            #endif
        elif selection == 1:
            print str(selection)+": Removing invalid urls entries"
            for document in self.urlsCollection.find({}):
                if document.has_key('url') and document['url']:
                    try:
                        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(document['url'])
                        if not (document.has_key('domain') and document['domain']):
                            document['domain'] = netloc
                            self.urlsCollection.save(document)
                        #endif
                    except ValueError:
                        print "Removing from urls: "+document['url']
                        self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                    #endtryexcept 
                else:
                    print "Removing from urls: "+document['url']
                    self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                #endif
            #endfor
        elif selection == 2:
            print str(selection)+": Removing invalid riscos entries"
            for document in self.riscosCollection.find({}):
                if document.has_key('url') and document['url']:
                    try:
                        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(document['url'])
                        if not (document.has_key('domain') and document['domain']):
                            document['domain'] = netloc
                            self.riscosCollection.save(document)
                        #endif
                    except ValueError:
                        print "Removing from riscos: "+document['url']
                        self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                    #endtryexcept 
                else:
                    print "Removing from riscos: "+document['url']
                    self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                #endif
            #endfor
        elif selection == 3:
            print str(selection)+": Remove web.archive.org urls entries where archived URL still exists"
            try:
                for document in self.urlsCollection.find({'domain':'web.archive.org'}):
                    if document.has_key('url') and document['url'] and document['url'].startswith('http://web.archive.org/'):
                        results = self.archivedUrlPattern.findall(document['url'])
                        if results:
                            if self.url_in_riscos(results[0]):
                                print 'Removing Living Archive '+document['url']+'...'
                                self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                            else:
                                if self.url_in_urls(results[0]):
                                    if not self.url_in_reserves(document['url']):
                                        print 'Moving Archive to Reserves '+document['url']+'...'
                                        newDocument = {}
                                        newDocument['url'] = document['url']
                                        self.reservesCollection.insert(newDocument)
                                        print "Inserting into reserves: "+newDocument['url']
                                    #endif
                                    print "Removing from urls: "+document['url']
                                    self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                                #endif
                            #endif
                        #endif
                    #endif
                #endfor
            except:
                True
        elif selection == 4:
            print str(selection)+": Remove web.archive.org riscos entries where archived URL still exists"
            try:
                for document in self.riscosCollection.find({'domain':'web.archive.org'}):
                    if document.has_key('url') and document['url'] and document['url'].startswith('http://web.archive.org/'):
                        results = self.archivedUrlPattern.findall(document['url'])
                        if results:
                            if self.url_in_riscos(results[0]):
                                print 'Removing Living Archive '+document['url']+'...'
                                self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                            #endif
                        #endif
                    #endif
                #endfor
            except:
                True
        elif selection == 5:
            urlsCount = self.urlsCollection.find({}).count()
            riscosCount = self.riscosCollection.find({}).count()
            if urlsCount < riscosCount:      
                print str(selection)+": Remove rejected documents older than a year from rejects collection"
                try:
                    for document in self.rejectsCollection.find({'last_scanned':{'$lt':epoch-self.periodYear}}):
                        if document.has_key('url') and document['url']:
                            print 'Forgetting reject: '+document['url']
                        #endif
                        print "Removing from rejects: "+document['url'] 
                        self.rejectsCollection.remove({'_id':ObjectId(document['_id'])})        
                    #endfor
                except:
                    True
            #endif
        elif selection == 6:
            print str(selection)+": Move documents older than a year from riscos collection to urls collection"
            try:
                total = self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$lt':epoch-self.periodYear}}).count()
                counter = 0
                for document in self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$lt':epoch-self.periodYear}}):
                    if document['url'].startswith('/'):
                        print 'Ignoring '+document['url']
                    else:
                        counter += 1
                        normalisedUrl = self.normalise_url(document['url'])
                        if not self.url_in_urls(normalisedUrl):
                            movedDocument = {}
                            movedDocument['url'] = normalisedUrl
                            if document.has_key('parent_url') and document['parent_url']:
                                movedDocument['parent_url'] = document['parent_url']
                            #endif
                            if document.has_key('rss_feed') and document['rss_feed']:
                                movedDocument['rss_feed'] = document['rss_feed']
                            #endif
                            print str(counter)+' of '+str(total)+' : Moving from riscos to urls: '+movedDocument['url']
                            if normalisedUrl.lower().endswith('.zip') or normalisedUrl.lower().__contains__('.zip?'):
                                movedDocument['zip_file'] = normalisedUrl
                                movedDocument['last_scanned'] = 0
                            else:
                                movedDocument['last_scanned'] = document['last_scanned']
                            #endif
                            if document.has_key('next_scan') and document['next_scan']:
                                movedDocument['next_scan'] = document['next_scan']
                            else:
                                movedDocument['next_scan'] = epoch
                            #endif
                            self.urlsCollection.insert(movedDocument)
                            print "Inserting into urls: "+movedDocument['url']
                        #endif
                        print "Removing from riscos: "+document['url']
                        self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                        if counter >= 32:
                            break
                        #endif
                    #endif
                #endfor
            except:
                True
        elif selection == 7:
            print str(selection)+": Identify software-specific documents"
            for document in self.urlsCollection.find({'url':{'$ne':''}}):
                if document.has_key('url') and document['url']:
                    softwareSpecific = False
                    for phrase in ['.arc','.spk','.zip','applications','apps','careware','downloads','freeware','package','programs','progs','shareware','software','utilities']:
                        if document['url'].lower().__contains__(phrase):
                            if document.has_key('domain') and not document['domain'] in ['web.archive.org','www.ebay.co.uk','jigsaw.w3.org']:
                                softwareSpecific = True
                                break
                            #endif
                        #endif
                    #endfor
                    if softwareSpecific:
                        document['last_scanned'] = 0
                        self.urlsCollection.save(document)
                    elif document.has_key('last_scanned') and document['last_scanned'] == 0:
                        document['last_scanned'] = 1
                        self.urlsCollection.save(document)
                    #endif
                #endif  
            #endfor
        elif selection == 8:
            print str(selection)+": Remove all documents with invalid hyperlink filetypes"
            for collection in [self.urlsCollection,self.riscosCollection]:
                for document in collection.find({'url':{'$ne':''}}):
                    if not self.valid_hyperlink_filetype(document['url']):
                        rejectDocument = {}
                        rejectDocument['url'] = document['url']
                        rejectDocument['last_scanned'] = epoch
                        self.rejectsCollection.insert(rejectDocument)          
                        print 'Inserting into rejects: '+document['url']
                        print "Removing: "+document['url']
                        collection.remove({'_id':ObjectId(document['_id'])})
                    #endif
                #endfor
            #endfor
        elif selection == 9:
            print str(selection)+": Removing duplicate riscos documents"
            self.remove_riscos_duplicates()
        elif selection == 10:
            print str(selection)+": Removing duplicate urls documents"
            self.remove_urls_duplicates()
            
            
            
        elif selection == 111111: # REVERT WHEN XML IMPLEMENTED!!!
        
        
        
        
            print str(selection)+": Remove older web.archive.org urls entries where newer archived urls entries exist"
            try:
                for document in self.urlsCollection.find({'domain':'web.archive.org'}):
                    if document.has_key('url') and document['url'] and document['url'].startswith('http://web.archive.org/'):
                        originalUrl = ""
                        crawlDate = ""
                        results = self.archivedUrlPattern.findall(document['url'])
                        if results:
                            originalUrl = results[0]
                        #endif
                        results = self.archivedDatePattern.findall(document['url'])
                        if results:
                            crawlDate = results[0]
                        #endif
                        if originalUrl and crawlDate:
                            for otherDocument in self.urlsCollection.find({'domain':'web.archive.org'}):
                                otherOriginalUrl = ""
                                otherCrawlDate = ""
                                results = self.archivedUrlPattern.findall(otherDocument['url'])
                                if results:
                                    otherOriginalUrl = results[0]
                                #endif
                                results = self.archivedDatePattern.findall(otherDocument['url'])
                                if results:
                                    otherCrawlDate = results[0]
                                #endif
                                if originalUrl == otherOriginalUrl and otherCrawlDate > crawlDate:
                                    print 'Removing older of archives as newer found: '+document['url']
                                    self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                                #endif
                            #endfor
                        #endif
                    #endif
                #endfor
            except:
                True
        elif selection == 12:
            print str(selection)+": Identify superseded applications"
            self.identify_superseded_applications()
        elif selection == 13:
            print str(selection)+": Unlink superseded applications where newer version no longer valid"
            self.unlink_previously_superseded_applications()
        elif selection == 14:
            print str(selection)+": Synchronise with other mirrors"
            self.synchronise_mirrors()
        elif selection == 15:
            print str(selection)+": Move documents whose next_scan value is lower than epoch"
            try:
                total = self.riscosCollection.find({'url':{'$ne':['']},'next_scan':{'$lt':epoch}}).count()
                counter = 0
                for document in self.riscosCollection.find({'url':{'$ne':['']},'next_scan':{'$lt':epoch}}):
                    if document['url'].startswith('/'):
                        print 'Ignoring '+document['url']
                    else:
                        counter += 1
                        normalisedUrl = self.normalise_url(document['url'])
                        if not self.url_in_urls(normalisedUrl):
                            movedDocument = {}
                            movedDocument['url'] = normalisedUrl
                            if document.has_key('parent_url') and document['parent_url']:
                                movedDocument['parent_url'] = document['parent_url']
                            #endif
                            if document.has_key('rss_feed') and document['rss_feed']:
                                movedDocument['rss_feed'] = document['rss_feed']
                            #endif
                            print str(counter)+' of '+str(total)+' : Moving from riscos to urls: '+movedDocument['url']
                            if normalisedUrl.lower().endswith('.zip') or normalisedUrl.lower().__contains__('.zip?'):
                                movedDocument['zip_file'] = normalisedUrl
                                movedDocument['last_scanned'] = 0
                            else:
                                movedDocument['last_scanned'] = document['last_scanned']
                            #endif
                            if document.has_key('next_scan') and document['next_scan']:
                                movedDocument['next_scan'] = document['next_scan']
                            else:
                                movedDocument['next_scan'] = epoch
                            #endif
                            self.urlsCollection.insert(movedDocument)
                            print "Inserting into urls: "+movedDocument['url']
                        #endif
                        print "Removing from riscos: "+document['url']
                        self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                        if counter >= 32:
                            break
                        #endif
                    #endif
                #endfor
            except:
                True
        #endif
        self.housekeepingTasksLastRan[selection] = int(time.time())
    #enddef
    
    def synchronise_mirrors(self):
        for mirror in self.mirrors:
            if mirror != self.mirror:
                req = urllib2.Request('http://'+mirror+'/synchronise')
                req.add_unredirected_header('User-Agent', 'RISC OS Search Engine http://'+mirror)
                try:
                    urlp = urllib2.urlopen(req)
                    data = urlp.read()
                    urlp.close()
                    print data
                except:
                    True
            #endif
        #endfor
    #enddef
    
    def spider(self):
        document = ""
        url = ""
        data = ""
        latestMessage = ""
        epoch = int(time.time())

        # Find a non-indexed document with a .zip-based URL
        doc_ids = self.urlsCollection.find({'zip_file':{'$ne':''},'last_scanned':0}).distinct('_id')
        if doc_ids:
            counter = 0
            while not url and counter < len(doc_ids):
                counter += 1
                document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                if document:
                    if document.has_key('url') and document['url']:
                        if (document['url'].lower().endswith('.zip') or document['url'].lower().__contains__('.zip?')):
                            if document['url'].startswith('/'):
                                self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                                print 'Removing from urls: '+document['url']
                            else:
                                url = document['url']
                                print "Processing [1] "+url+'...'
                                break
                            #endif
                        else:
                            try:
                                del document['zip_file']
                                self.urlsCollection.save(document)
                            except:
                                True
                        #endif
                    #endif
                #endif
            #endwhile
        #endif

        # Find an urgent non-.zip non-indexed document
        if not url:
            doc_ids = self.urlsCollection.find({'last_scanned':0}).distinct('_id')
            if doc_ids:
                counter = 0
                while not url and counter < len(doc_ids):
                    counter += 1
                    document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                    if document.has_key('url') and document['url']:
                        url = document['url']
                        print "Processing [2] "+url+'...'
                    #endif
                #endwhile
            #endif
        #endif

        # Attempt to find a riscos.xml file
        if not url:
            doc_ids = self.urlsCollection.find({'riscos_xml':{'$exists':True}}).distinct('_id')
            if doc_ids:
                counter = 0
                while not url and counter < len(doc_ids):
                    counter += 1
                    document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                    if document.has_key('url') and document['url']:
                        url = document['url']
                        print "Processing [3] "+url+'...'
                    #endif
                #endwhile
            #endif
        #endif        
        
        # Attempt to find an RSS feed directly
        if not url:
            doc_ids = self.urlsCollection.find({'rss_feed':{'$exists':True}}).distinct('_id')
            if doc_ids:
                counter = 0
                while not url and counter < len(doc_ids):
                    counter += 1
                    document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                    if document.has_key('url') and document['url']:
                        url = document['url']
                        print "Processing [4] "+url+'...'
                    #endif
                #endwhile
            #endif
        #endif
        
        # Attempt to find an RSS feed indirectly
        if not url:
            searchCriteria = {}
            searchCriteria['url'] = re.compile('(?i)\.(?:rss|xml)$')
            for document in self.urlsCollection.find(searchCriteria):
                if document['url'].lower.endswith('.rss') or document['url'].lower.endswith('.xml'):
                    url = document['url']
                    print "Processing [5] "+url+'...'
                #endif
            #endfor
        #endif 
        
        # Attempt to find an ftp site
        if not url:
            searchCriteria = {}
            searchCriteria['url'] = re.compile('(?i)^ftp://')
            for document in self.urlsCollection.find(searchCriteria):
                if document['url'].lower.startswith('ftp://'):
                    url = document['url']
                    print "Processing [6] "+url+'...'
                #endif
            #endfor
        #endif 

        # Attempt to find a document whose next_scan is lower than epoch
        if not url:
            doc_ids = self.urlsCollection.find({'url':{'$ne':['']},'next_scan':{'$lt':epoch}}).distinct('_id')
            if doc_ids:
                counter = 0
                while not url and counter < len(doc_ids):
                    counter += 1
                    document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                    url = document['url']
                    print "Processing [7] "+url+'...'
                #endwhile
            #endif
        #endif        

        # Attempt to find a non-indexed URL that is from the domain with the least documents
        if not url:
            domains = []
            for domain in self.urlsCollection.find({'url':{'$ne':''},'domain':{'$ne':''}}).distinct('domain'):
                count = self.urlsCollection.find({'domain':domain}).count()
                if count < 32:
                    domains.append(domain)
                #endif
            #endfor
            if domains:
                doc_ids = self.urlsCollection.find({'url':{'$ne':''},'domain':domains[randint(0,len(domains)-1)]}).distinct('_id')
                if doc_ids:
                    counter = 0
                    while not url and counter < len(doc_ids):
                        counter += 1
                        document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                        url = document['url']
                        print "Processing [8] "+url+'...'
                    #endwhile
                #endif
            #endif
        #endif   
        
        # Attempt to find a non-indexed URL
        if not url:
            doc_ids = self.urlsCollection.find({'url':{'$ne':''}}).distinct('_id')
            if doc_ids:
                counter = 0
                while not url and counter < len(doc_ids):
                    counter += 1
                    document = self.urlsCollection.find_one({'_id':ObjectId(doc_ids[randint(0,len(doc_ids)-1)])})
                    url = document['url']
                    print "Processing [9] "+url+'...'
                #endwhile
            #endif
        #endif

        if not url or not document:
            latestMessage = 'All spidering is now up-to-date!'
            return latestMessage 
        #endif
        url = self.normalise_url(url)
        
        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
        except ValueError:
            # Possibly due to a IPv6 URL
            rejectDocument = {}
            rejectDocument['url'] = url
            rejectDocument['last_scanned'] = epoch
            self.rejectsCollection.insert(rejectDocument)
            print "Inserting into rejects: "+rejectDocument['url']
            self.urlsCollection.remove({'url':url})
            print 'Removing from urls: '+url
            latestMessage = 'A possible IPv6 url at '+url+', so duly removed!'
            return latestMessage
        #endtryexcept

        document['url'] = url
        
        if self.blacklisted_document(document):
            print "Removing blacklisted url: "+document['url']
            latestMessage = "Removing blacklisted url: "+document['url']
            self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
            return latestMessage
        #endif

        if self.suspended_document(document):
            print "Suspending url: "+document['url']
            latestMessage = "Suspending url: "+document['url']
            reserveDocument = {}
            reserveDocument['url'] = document['url']
            reserveDocument['last_scanned'] = epoch
            self.reservesCollection.insert(reserveDocument)
            print 'Inserting into reserves: '+document['url']
            self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
            return latestMessage
        #endif         
        
        self.urlsCollection.save(document)

        try:
            (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
            req = urllib2.Request(scheme+'://'+netloc+'/robots.txt')
            req.add_unredirected_header('User-Agent', 'RISC OS Search Engine http://www.shalfield.com/riscos')
            urlp = urllib2.urlopen(req)
            data = urlp.read()
            urlp.close()
            userAgentSections = data.split('User-agent: ')
            disallowed = False
            for userAgentSection in userAgentSections:
                escapedPath = path.replace('+','\+')
                if userAgentSection.startswith('*') and (re.search('Disallow: /\s', userAgentSection) or re.search('Disallow: '+escapedPath, userAgentSection)):
                    print userAgentSection
                    disallowed = True
                #endif
            #endfor
            if disallowed:
                rejectDocument = {}
                rejectDocument['url'] = url
                rejectDocument['last_scanned'] = epoch
                self.rejectsCollection.insert(rejectDocument)
                print "Inserting into rejects: "+rejectDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url          
                latestMessage = 'Disallowed access to <a href="'+url+'">'+url+'</a> due to robots.txt!'
                
                try:
                    for document in self.urlsCollection.find({'url':{"$exists":True,"$ne":""}}):
                        if document.has_key('url') and document['url']:
                            try:
                                (altScheme,altNetloc,altPath,altQuery,altFragment) = urlparse.urlsplit(document['url'])
                                if altPath == path and altNetloc == netloc and  altScheme == scheme:
                                    rejectDocument = {}
                                    rejectDocument['url'] = document['url']
                                    rejectDocument['last_scanned'] = epoch
                                    self.rejectsCollection.insert(rejectDocument)
                                    print "Inserting into rejects: "+rejectDocument['url']
                                    self.urlsCollection.remove({'url':document['url']})
                                    print 'Removing from urls: '+document['url']
                                #endif
                            except:
                                True
                        #endif
                    #endfor
                except:
                    True
                
                return latestMessage
            #endif
        except HTTPError, error:
            if error.code == 404:
                True
            #endif
        except urllib2.URLError:
            True
        except socket.timeout:
            True    

        try:
            print "Attempting to connect to "+url
            req = urllib2.Request(url)
            req.add_unredirected_header('User-Agent', 'RISC OS Search Engine http://www.shalfield.com/riscos')
            urlp = urllib2.urlopen(req)
            data = urlp.read()
            urlp.close()
            document['strikes'] = 0
            self.urlsCollection.save(document)
            self.lastSuccessfulInternetConnection = epoch
            print 'Successfully read '+url
            print "Data length is "+str(len(data))
        except socket.timeout:
            latestMessage = 'We have suffered a socket timeout whilst trying to reach <a href="'+url+'">'+url+'</a> so will try again later!'
            return latestMessage
        except SSLError:
            # The read operation timed out
            if document.has_key('seed') and document['seed'] == True:
                latestMessage = 'Unable to reach <a href="'+url+'">'+url+'</a> so will try again later!'
                return latestMessage
            else:
                if self.lastSuccessfulInternetConnection >= epoch-60:
                    rejectDocument = {}
                    rejectDocument['url'] = url
                    rejectDocument['last_scanned'] = epoch
                    self.rejectsCollection.insert(rejectDocument)
                    print "Inserting into rejects: "+rejectDocument['url']
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> is unreachable so it has now been removed!'
                else:
                    if document.has_key('strikes'):
                        if document['strikes'] == 2 and self.lastSuccessfulInternetConnection >= epoch-60:
                            rejectDocument = {}
                            rejectDocument['url'] = url
                            rejectDocument['last_scanned'] = epoch
                            self.rejectsCollection.insert(rejectDocument)
                            print "Inserting into rejects: "+rejectDocument['url']
                            self.urlsCollection.remove({'url':url})
                            print 'Removing from urls: '+url
                            latestMessage = 'Three strikes raised against <a href="'+url+'">'+url+'</a> so it has now been removed!'
                        else:
                            document['strikes'] += 1
                            document['last_scanned'] = epoch
                            document['next_scan'] = epoch + self.periodWeek
                            self.urlsCollection.save(document)
                            latestMessage = 'Another strike has been raised against <a href="'+url+'">'+url+'</a> as no longer reachable!'
                        #endif
                    else:
                        document['strikes'] = 1
                        document['last_scanned'] = epoch
                        document['next_scan'] = epoch + self.periodWeek
                        self.urlsCollection.save(document)
                        latestMessage = 'A strike has been raised against <a href="'+url+'">'+url+'</a> as it is unreachable!'
                        return latestMessage
                    #endif
                #endif
            #endif       
        except HTTPError, error:
            if error.code >= 400 and error.code <= 499:
                rejectDocument = {}
                rejectDocument['url'] = url
                rejectDocument['last_scanned'] = epoch
                self.rejectsCollection.insert(rejectDocument)
                print "Inserting into rejects: "+rejectDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                if hasattr(error, 'reason'):
                    latestMessage = str(error.code)+' ('+error.reason+') error with '+url+', so duly removed!'
                else:
                    latestMessage = str(error.code)+' error with '+url+', so duly removed!'
                #endif
                return latestMessage 
            #endif
        except ValueError:
            if self.lastSuccessfulInternetConnection >= epoch-60:
                rejectDocument = {}
                rejectDocument['url'] = url
                rejectDocument['last_scanned'] = epoch
                self.rejectsCollection.insert(rejectDocument)
                print "Inserting into rejects: "+rejectDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Bad url, '+url+', so duly removed!'
                return latestMessage
            #endif
        except httplib.InvalidURL:
            if self.lastSuccessfulInternetConnection >= epoch-60:
                rejectDocument = {}
                rejectDocument['url'] = url
                rejectDocument['last_scanned'] = epoch
                self.rejectsCollection.insert(rejectDocument)
                print "Inserting into rejects: "+rejectDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Bad url, '+url+', so duly removed!'
                return latestMessage
            #endif
        except urllib2.URLError:
            if document.has_key('seed') and document['seed'] == True:
                latestMessage = 'Unable to reach <a href="'+url+'">'+url+'</a> so will try again later!'
                return latestMessage
            else:
                if self.lastSuccessfulInternetConnection >= epoch-60:
                    rejectDocument = {}
                    rejectDocument['url'] = url
                    rejectDocument['last_scanned'] = epoch
                    self.rejectsCollection.insert(rejectDocument)
                    print "Inserting into rejects: "+rejectDocument['url']
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> is unreachable so it has now been removed!'
                    return latestMessage
                else:
                    if document.has_key('strikes'):
                        if document['strikes'] == 2 and self.lastSuccessfulInternetConnection >= epoch-60:
                            rejectDocument = {}
                            rejectDocument['url'] = url
                            rejectDocument['last_scanned'] = epoch
                            self.rejectsCollection.insert(rejectDocument)
                            print "Inserting into rejects: "+rejectDocument['url']
                            self.urlsCollection.remove({'url':url})
                            print 'Removing from urls: '+url
                            latestMessage = 'Three strikes raised against <a href="'+url+'">'+url+'</a> so it has now been removed!'
                            return latestMessage
                        else:
                            document['strikes'] += 1
                            document['last_scanned'] = epoch
                            document['next_scan'] = epoch + self.periodWeek
                            self.urlsCollection.save(document)
                            latestMessage = 'Another strike has been raised against <a href="'+url+'">'+url+'</a> as no longer reachable!'
                            return latestMessage
                        #endif
                    else:
                        document['strikes'] = 1
                        document['last_scanned'] = epoch
                        document['next_scan'] = epoch + self.periodWeek
                        self.urlsCollection.save(document)
                        latestMessage = 'A strike has been raised against <a href="'+url+'">'+url+'</a> as it is unreachable!'
                        return latestMessage
                    #endif
                #endif
            #endif
        #endtryexcept
            
        if len(data) == 0:
            rejectDocument = {}
            rejectDocument['url'] = url
            rejectDocument['last_scanned'] = epoch
            self.rejectsCollection.insert(rejectDocument)
            print "Inserting into rejects: "+rejectDocument['url']        
            self.urlsCollection.remove({'url':url})
            print 'Removing from urls: '+url
            latestMessage = 'Although <a href="'+url+'">'+url+'</a> was successfully read, no data was returned'
            return latestMessage          
        else:
            metaRobotsResults = self.metaRobotsPattern.findall(data)
            if metaRobotsResults and metaRobotsResults[0].__contains__('noindex'):
                rejectDocument = {}
                rejectDocument['url'] = url
                rejectDocument['last_scanned'] = epoch
                self.rejectsCollection.insert(rejectDocument)
                print "Inserting into rejects: "+rejectDocument['url']        
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Although <a href="'+url+'">'+url+'</a> was successfully read, indexing is disallowed'
                return latestMessage
            #endif
        
            if url.lower().endswith('.arc'):
                print 'Analysing '+url+' as Archive file...'
                newDocument = {}
                newDocument['url'] = url
                newDocument['arc_file'] = url
                newDocument['last_scanned'] = epoch
                newDocument['next_scan'] = epoch + self.periodYear
                self.riscosCollection.insert(newDocument)
                print "Inserting into riscos: "+newDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, an elderly archive file'
                return latestMessage
            elif url.lower().endswith('.spk'):
                print 'Analysing '+url+' as SPK file...'
                newDocument = {}
                newDocument['url'] = url
                newDocument['spark_file'] = url
                newDocument['last_scanned'] = epoch
                newDocument['next_scan'] = epoch + self.periodYear
                self.riscosCollection.insert(newDocument)
                print "Inserting into riscos: "+newDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, an elderly archive file'
                return latestMessage
            elif url.lower().endswith('.pdf'):
                print 'Analysing '+url+' as PDF file...'
                newDocument = {}
                newDocument['url'] = url
                newDocument['pdf_file'] = url
                newDocument['last_scanned'] = epoch
                newDocument['next_scan'] = epoch + self.periodYear
                self.riscosCollection.insert(newDocument)
                print "Inserting into riscos: "+newDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, a Portable Document Format file'
                return latestMessage
            elif url.lower().endswith('/riscos.xml'):
                print 'Processing '+url+' as riscos.xml file...'
                self.process_riscos_xml_file(url, data)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, a riscos.xml file'
                return latestMessage
            elif url.lower().endswith('.rss') or url.lower().endswith('.xml') or re.search('<rss(.*?)</rss>',data):
                print 'Analysing '+url+' as RSS feed...'
                self.analyse_rss_feed(url, data)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, an RSS Feed'
                return latestMessage
            elif url.lower().endswith('.zip') or url.lower().__contains__('.zip?'):
                print 'Analysing '+url+' as ZIP file...'
                try:
                    apps = self.analyse_zip_file(data)
                    self.update_apps(url,document,apps)
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'Indexing <a href="'+url+'">'+url+'</a>'
                    return latestMessage
                except zipfile.BadZipfile:
                    newDocument = {}
                    newDocument['url'] = url
                    newDocument['zip_file'] = url
                    newDocument['error'] = 'Bad Zip File'
                    newDocument['last_scanned'] = epoch
                    newDocument['next_scan'] = epoch + self.periodYear
                    self.riscosCollection.insert(newDocument)
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'Bad zipfile encountered at <a href="'+url+'">'+url+'</a>'
                    return latestMessage                    
            elif self.page_riscos_related(data):
                print 'Analysing '+url+' as something RISC OS related...'
                baseUrl = ""
                results = self.baseUrlPattern.findall(data)
                if results:
                    baseUrl = results[0]
                #endif

                if urlp.headers.has_key('content-type') and urlp.headers['content-type'].startswith('text/html'):
                    results = self.titlePattern.findall(data)
                    if results:
                        try:
                            if not self.url_in_rejects(url):
                                newDocument = {}
                                newDocument['url'] = url
                                newDocument['page_title'] = results[0]
                                newDocument['last_scanned'] = epoch
                                newDocument['next_scan'] = epoch + self.periodYear
                                self.riscosCollection.insert(newDocument)
                                print "Inserting into riscos: "+newDocument['url']
                            #endif
                        except:
                            True
                    #endif
                #endif
                
                if urlp.headers.has_key('last-modified') and urlp.headers['last-modified']:
                    rawLastModified = urlp.headers['last-modified']
                    try:
                        document['last_scanned'] = epoch
                        document['next_scan'] = epoch + self.periodYear
                        document['last_modified'] = int(time.mktime(time.strptime(rawLastModified[5:25],"%d %b %Y %H:%M:%S")))
                        self.riscosCollection.save(document)
                    except:
                        True
                #endif                
                
                if document.has_key('page_title') and document['page_title']:
                    try:
                        latestMessage = 'Indexing <a href="'+url+'" title="'+url+'">'+document['page_title']+'</a>'
                        document['last_scanned'] = epoch
                        document['next_scan'] = epoch + self.periodYear
                        self.riscosCollection.save(document)
                    except:
                        True
                else:
                    try:
                        latestMessage = 'Indexing <a href="'+url+'">'+url+'</a>'
                        document['last_scanned'] = epoch
                        document['next_scan'] = epoch + self.periodYear
                        self.riscosCollection.save(document)
                    except:
                        True
                #endif
                
                if not self.url_pre_validation(document, data):
                    self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                    print 'Removing from riscos: '+document['url']
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> has failed pre-validation'
                    return latestMessage
                #endif

                results = self.externalLinkPattern.findall(data)
                for result in results:
                    try:
                        # Splits url into scheme, netloc, path, params, query, fragment
                        urlComponents = urlparse.urlsplit(result)
                        # Remove the params, query or fragment from the URL line
                        if urlComponents.params or urlComponents.query or urlComponents.fragment:
                            result = urlparse.urlunsplit((urlComponents.scheme,urlComponents.netloc,urlComponents.path,'',''))
                        #endif
                        if self.valid_hyperlink_filetype(result) and not result.startswith('../'):
                            if not self.url_in_riscos(result) and not self.url_in_urls(result) and not self.url_in_rejects(result) and not self.url_in_reserves(result) and not self.suspended_url(result) and not self.blacklisted_url(result):
                                subDocument = {}
                                subDocument['url'] = result
                                subDocument['parent_url'] = url
                                subDocument['last_scanned'] = 1                             
                                self.urlsCollection.insert(subDocument)
                                print "Inserting into urls: "+subDocument['url']
                            #endif
                        #endif
                    except:
                        True
                    #endtryexcept
                #endfor              

                metaRobotsResults = self.metaRobotsPattern.findall(data)
                if metaRobotsResults and metaRobotsResults[0].__contains__('nofollow'):
                    print "Internal links within URL can't be followed as disallowed by meta robots"
                else:
                    results = self.internalLinkPattern.findall(data)
                    if results != []:
                        for result in results:
                            if self.valid_hyperlink_filetype(result):
                                if result.startswith('ftp://') or result.startswith('http://') or result.startswith('https://'):
                                    True
                                elif baseUrl:
                                    try:
                                        result = urlparse.urljoin(baseUrl,result)
                                    except:
                                        result = ""
                                else:
                                    try:
                                        result = urlparse.urljoin(url,result)
                                    except:
                                        result = ""
                                #endif
                                if result:
                                    if not self.url_in_riscos(result) and not self.url_in_urls(result) and not self.url_in_rejects(result) and not self.url_in_reserves(result) and not self.suspended_url(result) and not self.blacklisted_url(result):
                                        subDocument = {}
                                        subDocument['url'] = result
                                        subDocument['parent_url'] = url
                                        subDocument['last_scanned'] = 1                                
                                        self.urlsCollection.insert(subDocument)
                                        print "Inserting into urls: "+subDocument['url']
                                    #endif
                                #endif
                            #endif
                        #endfor
                    #endif
                #endif

                if not self.url_post_validation(document['url'], data):
                    self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                    print 'Removing from riscos: '+document['url']
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> has failed post-validation'
                    return latestMessage
                #endif
                
                if document['url'].__contains__('youtube') and data.__contains__('//www.youtube.com/embed/'):
                    results = self.youTubeEmbedPattern.findall(data)
                    if results:
                        embedString = results[0]
                        embedString = embedString.replace('&lt;','<')
                        embedString = embedString.replace('&gt;','>')
                        document['embed'] = embedString
                        self.riscosCollection.save(document)
                    #endif
                #endif
                
                self.riscos_xml_search(url)
            else:
                print 'Analysing '+url+' as default...'
                if url and self.lastSuccessfulInternetConnection >= epoch-60:
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    rejectDocument = {}
                    rejectDocument['url'] = url
                    rejectDocument['last_scanned'] = epoch
                    self.rejectsCollection.insert(rejectDocument)
                    print "Inserting into rejects: "+rejectDocument['url']
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> has been rejected as not RISC OS-related!'
                #endif
            #endif
        #endif
        return latestMessage
    #enddef    
    
    def riscos_xml_search(self,url):
        epoch = int(time.time())
        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
        riscos_xml_urls = [scheme+'://'+netloc+'/riscos.xml',scheme+'://'+netloc+'/'+path+'/riscos.xml']
        for riscos_xml_url in riscos_xml_urls:
            if not self.url_in_riscos(riscos_xml_url) and not self.url_in_urls(riscos_xml_url) and not self.url_in_rejects(riscos_xml_url) and not self.url_in_reserves(riscos_xml_url) and not self.suspended_url(riscos_xml_url) and not self.blacklisted_url(riscos_xml_url):
                print 'Searching for '+url+'...'
                req = urllib2.Request(riscos_xml_url)
                req.add_unredirected_header('User-Agent', 'RISC OS Search Engine http://www.shalfield.com/riscos')
                found = True
                try:
                    urlp = urllib2.urlopen(req)
                    data = urlp.read()
                    urlp.close()
                    if data:
                        self.process_riscos_xml_file(url,data)       
                    #endif
                except HTTPError, error:
                    if error.code == 404:
                        found = False
                    #endif
                except urllib2.URLError:
                    found = False
                except socket.timeout:
                    found = False
                #endtryexcept
                if not found:
                    newDocument = {}
                    newDocument['url'] = url
                    newDocument['last_scanned'] = epoch
                    newDocument['next_scan'] = epoch + self.periodYear
                    self.rejectsCollection.insert(newDocument)           
                #endif
                if found:
                    break
                #endif
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_file(self, parent_url, xmlcode):
        print 'Processing '+parent_url+'...'
        try:
            riscos = etree.XML(xmlcode)
            #print etree.tostring(riscos, pretty_print=True)
            for subelement in riscos.iter():
                if subelement.tag.lower() == 'developers':
                    self.process_riscos_xml_developers_element(parent_url, subelement)
                elif subelement.tag.lower() == 'events':
                    self.process_riscos_xml_events_element(parent_url, subelement)
                elif subelement.tag.lower() == 'forums':
                    self.process_riscos_xml_forums_element(parent_url, subelement)
                elif subelement.tag.lower() == 'glossary':
                    self.process_riscos_xml_glossary_element(parent_url, subelement)
                elif subelement.tag.lower() == 'hardware':
                    self.process_riscos_xml_hardware_element(parent_url, subelement)
                elif subelement.tag.lower() == 'publications':
                    self.process_riscos_xml_publications_element(parent_url, subelement)
                elif subelement.tag.lower() == 'services':
                    self.process_riscos_xml_services_element(parent_url, subelement)   
                elif subelement.tag.lower() == 'software':
                    self.process_riscos_xml_software_element(parent_url, subelement)
                elif subelement.tag.lower() in ['user_groups','usergroups']:
                    self.process_riscos_xml_usergroups_element(parent_url, subelement)
                elif subelement.tag.lower() == 'videos':
                    self.process_riscos_xml_videos_element(parent_url, subelement)                    
                #endif
            #endfor
        except:
            True
    #enddef

    def process_riscos_xml_developers_element(self, parent_url, developersElement):
        print 'Processing '+developersElement.tag+'...'
        for subelement in developersElement.iter():
            if subelement.tag.lower() == 'developer':
                self.process_riscos_xml_developer_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_developer_element(self, parent_url, developerElement):
        epoch = int(time.time())
        developer = ""
        address = ""
        description = ""
        email = ""
        telephone = ""
        url = ""
        print 'Processing '+developerElement.tag+'...'
        #xmlcode = etree.tostring(developerElement)
        #print xmlcode
        for subelement in developerElement.iter():
            if subelement.tag.lower() == 'address':
                address = subelement.text
                print 'Address: '+address
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'email':
                email = subelement.text
                print 'Email: '+email    
            elif subelement.tag.lower() == 'name':
                developer = subelement.text
                print 'Developer: '+developer
            elif subelement.tag.lower() == 'telephone':
                telephone = subelement.text
                print 'Telephone: '+telephone
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if developer and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['developer'] = developer
            newDocument['address'] = address
            newDocument['description'] = description
            newDocument['email'] = email
            newDocument['telephone'] = telephone
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef 

    def process_riscos_xml_events_element(self, parent_url, eventsElement):
        print 'Processing '+eventsElement.tag+'...'
        for subelement in eventsElement.iter():
            if subelement.tag.lower() == 'event':
                self.process_riscos_xml_event_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_event_element(self, parent_url, eventElement):
        epoch = int(time.time())
        event = ""
        date = ""
        description = ""
        url = ""
        print 'Processing '+eventElement.tag+'...'
        #xmlcode = etree.tostring(eventElement)
        #print xmlcode
        for subelement in eventElement.iter():
            if subelement.tag.lower() == 'date':
                day = ""
                month = ""
                year = ""
                for attr, value in subelement.items():
                    if attr.lower() == 'day':
                        day = value
                    elif attr.lower() == 'month':
                        month = value
                    elif attr.lower() == 'year':
                        year = value
                    #endif
                #endfor
                date = year+'-'+month+'-'+day
                print 'Date: '+year+'-'+month+'-'+day
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description   
            elif subelement.tag.lower() == 'title':
                event = subelement.text
                print 'Event: '+event
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if developer and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['date'] = date
            newDocument['event'] = event
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef     

    def process_riscos_xml_forums_element(self, parent_url, forumsElement):
        print 'Processing '+forumsElement.tag+'...'
        for subelement in forumsElement.iter():
            if subelement.tag.lower() == 'forum':
                self.process_riscos_xml_forum_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_forum_element(self, parent_url, forumElement):
        epoch = int(time.time())
        forum = ""
        description = ""
        url = ""
        print 'Processing '+forumElement.tag+'...'
        #xmlcode = etree.tostring(forumElement)
        #print xmlcode
        for subelement in forumElement.iter():
            if subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description   
            elif subelement.tag.lower() == 'name':
                forum = subelement.text
                print 'Forum: '+forum
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if developer and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['forum'] = forum
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef     

    def process_riscos_xml_hardware_element(self, parent_url, hardwareElement):
        print 'Processing '+hardwareElement.tag+'...'
        for subelement in hardwareElement.iter():
            if subelement.tag.lower() == 'computers':
                self.process_riscos_xml_computers_element(parent_url, subelement)            
            elif subelement.tag.lower() == 'podules':
                self.process_riscos_xml_podules_element(parent_url, subelement)
            #endif
        #endfor            
    #enddef
    
    def process_riscos_xml_computers_element(self, parent_url, computersElement):
        print 'Processing '+computersElement.tag+'...'
        for subelement in computersElement.iter():
            if subelement.tag.lower() == 'computer':
                self.process_riscos_xml_computer_element(parent_url, subelement)            
            #endif
        #endfor
    #enddef

    def process_riscos_xml_computer_element(self, parent_url, computerElement):
        developer = ""
        description = ""
        computer = ""
        url = ""
        print 'Processing '+computerElement.tag+'...'
        for subelement in computerElement.iter():
            if subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'developer':
                developer = subelement.text
                print 'Developer: '+developer
            elif subelement.tag.lower() == 'name':
                computer = subelement.text
                print 'Computer: '+computer
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if absolute and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['computer'] = computer
            newDocument['developer'] = developer
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef
    
    def process_riscos_xml_podules_element(self, parent_url, podulesElement):
        print 'Processing '+podulesElement.tag+'...'
        for subelement in podulesElement.iter():
            if subelement.tag.lower() == 'podule':
                self.process_riscos_xml_podule_element(parent_url, subelement)            
            #endif
        #endfor
    #enddef

    def process_riscos_xml_podule_element(self, parent_url, poduleElement):
        developer = ""
        description = ""
        podule = ""
        url = ""
        print 'Processing '+poduleElement.tag+'...'
        for subelement in poduleElement.iter():
            if subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'developer':
                developer = subelement.text
                print 'Developer: '+developer
            elif subelement.tag.lower() == 'name':
                podule = subelement.text
                print 'Podule: '+podule
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if absolute and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['podule'] = podule
            newDocument['developer'] = developer
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef    
    
    def process_riscos_xml_publications_element(self, parent_url, publicationsElement):
        print 'Processing '+publicationsElement.tag+'...'
        for subelement in developersElement.iter():
            if subelement.tag.lower() == 'books':
                self.process_riscos_xml_books_element(parent_url, subelement)
            elif subelement.tag.lower() == 'magazines':
                self.process_riscos_xml_magazines_element(parent_url, subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_books_element(self, parent_url, booksElement):
        print 'Processing '+booksElement.tag+'...'
        for subelement in booksElement.iter():
            if subelement.tag.lower() == 'book':
                self.process_riscos_xml_book_element(parent_url, subelement)
            #endif
        #endfor
    #enddef    
    
    def process_riscos_xml_book_element(self, parent_url, bookElement):
        description = ""
        isbn = ""
        price = ""
        publisher = ""
        title = ""
        url = ""        
        print 'Processing '+bookElement.tag+'...'
        for subelement in bookElement.iter():
            if subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'isbn':
                isbn = subelement.text
                print 'ISBN: '+isbn
            elif subelement.tag.lower() == 'price':
                currency = ""
                for attr, value in subelement.items():
                    if attr == 'currency':
                        currency = value
                    #endif
                #endfor
                price = subelement.text+currency
                print 'Price: '+price
            elif subelement.tag.lower() == 'publisher':
                publisher = subelement.text
                print 'Publisher: '+publisher
            elif subelement.tag.lower() == 'title':
                title = subelement.text
                print 'Title: '+title
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if absolute and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['book'] = title
            newDocument['identifier'] = isbn
            newDocument['price'] = price
            newDocument['publisher'] = publisher
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef 

    def process_riscos_xml_magazines_element(self, parent_url, magazinesElement):
        print 'Processing '+magazinesElement.tag+'...'
        for subelement in magazinesElement.iter():
            if subelement.tag.lower() == 'magazine':
                self.process_riscos_xml_magazine_element(parent_url, subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_magazine_element(self, parent_url, magazineElement):
        description = ""
        issn = ""
        price = ""
        publisher = ""
        title = ""
        url = ""        
        print 'Processing '+magazineElement.tag+'...'
        for subelement in magazineElement.iter():
            if subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'issn':
                issn = subelement.text
                print 'ISSN: '+issn
            elif subelement.tag.lower() == 'price':
                currency = ""
                for attr, value in subelement.items():
                    if attr == 'currency':
                        currency = value
                    #endif
                #endfor
                price = subelement.text+currency
                print 'Price: '+price
            elif subelement.tag.lower() == 'publisher':
                publisher = subelement.text
                print 'Publisher: '+publisher
            elif subelement.tag.lower() == 'title':
                title = subelement.text
                print 'Title: '+title
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if absolute and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['magazine'] = title
            newDocument['identifier'] = issn
            newDocument['price'] = price
            newDocument['publisher'] = publisher
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef 
    
    def process_riscos_xml_services_element(self, parent_url, servicesElement):
        print 'Processing '+servicesElement.tag+'...'
        for subelement in servicesElement.iter():
            if subelement.tag.lower() == 'service':
                self.process_riscos_xml_service_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_service_element(self, parent_url, serviceElement):
        epoch = int(time.time())
        provider = ""
        address = ""
        category = ""
        description = ""
        email = ""
        telephone = ""
        url = ""
        print 'Processing '+serviceElement.tag+'...'
        #xmlcode = etree.tostring(serviceElement)
        #print xmlcode
        for subelement in serviceElement.iter():
            if subelement.tag.lower() == 'address':
                address = subelement.text
                print 'Address: '+address
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'email':
                email = subelement.text
                print 'Email: '+email    
            elif subelement.tag.lower() == 'name':
                provider = subelement.text
                print 'Provider: '+provider
            elif subelement.tag.lower() == 'telephone':
                telephone = subelement.text
                print 'Telephone: '+telephone
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if provider and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['provider'] = provider
            newDocument['address'] = address
            newDocument['category'] = category
            newDocument['description'] = description
            newDocument['email'] = email
            newDocument['telephone'] = telephone
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef 
    
    def process_riscos_xml_software_element(self, parent_url, softwareElement):
        print 'Processing '+softwareElement.tag+'...'
        #xmlcode = etree.tostring(softwareElement)
        #print xmlcode
        for subelement in softwareElement.iter():
            if subelement.tag.lower() == 'absolutes':
                self.process_riscos_xml_absolutes_element(parent_url, subelement)            
            elif subelement.tag.lower() == 'apps':
                self.process_riscos_xml_apps_element(parent_url, subelement)
            elif subelement.tag.lower() == 'fonts':
                self.process_riscos_xml_fonts_element(parent_url, subelement)
            elif subelement.tag.lower() in ['modules','relocatablemodules'] or subelement.tag.lower() in ['relocatable_modules']:
                self.process_riscos_xml_modules_element(parent_url, subelement)
            elif subelement.tag.lower() == 'monitor_definition_files' or subelement.tag.lower() in ['monitordefinitionfiles','mdfs']:
                self.process_riscos_xml_monitor_definition_files_element(parent_url, subelement)
            elif subelement.tag.lower() == 'printer_definition_files' or subelement.tag.lower() in ['printerdefinitionfiles','pdfs']:
                self.process_riscos_xml_printer_definition_files_element(parent_url, subelement)
            elif subelement.tag.lower() == 'utilities':
                self.process_riscos_xml_utilities_element(parent_url, subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_absolutes_element(self, parent_url, absolutesElement):
        print 'Processing '+absolutesElement.tag+'...'
        for subelement in absolutesElement.iter():
            if subelement.tag.lower() == 'absolute':
                self.process_riscos_xml_absolute_element(parent_url, subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_absolute_element(self, parent_url, absoluteElement):
        epoch = int(time.time())
        absolute = ""
        url = ""
        print 'Processing '+absoluteElement.tag+'...'
        #xmlcode = etree.tostring(absoluteElement)
        #print xmlcode
        for subelement in absoluteElement.iter():
            if subelement.tag.lower() == 'name':
                absolute = subelement.text
                print 'Absolute: '+absolute
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if absolute and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['absolutes'] = [absolute]
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef
    
    def process_riscos_xml_apps_element(self, parent_url, appsElement):
        print 'Processing '+appsElement.tag+'...'
        #xmlcode = etree.tostring(appsElement)
        #print xmlcode
        for subelement in appsElement.iter():
            if subelement.tag.lower() == 'app':
                self.process_riscos_xml_app_element(parent_url, subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_app_element(self, parent_url, softwareElement):
        author = ""
        copyright = ""
        date = ""
        description = ""
        developer = ""
        directory = ""
        license = ""
        maintainer = ""
        name = ""
        price = ""
        url = ""
        version = ""
        print 'Processing '+softwareElement.tag+'...'
        #xmlcode = etree.tostring(softwareElement)
        #print xmlcode
        for subelement in softwareElement.iter():
            if subelement.tag.lower() == 'author':
                author = subelement.text
                print 'Author: '+author
            elif subelement.tag.lower() == 'copyright':
                copyright = subelement.text
                print 'Copyright: '+copyright
            elif subelement.tag.lower() == 'released':
                day = ""
                month = ""
                year = ""
                for attr, value in subelement.items():
                    if attr.lower() == 'day':
                        day = value
                    elif attr.lower() == 'month':
                        month = value
                    elif attr.lower() == 'year':
                        year = value
                    #endif
                #endfor
                print 'Date: '+day+'-'+month+'-'+year
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'developer':
                developer = subelement.text
                print 'Developer: '+developer
            elif subelement.tag.lower() == 'directory':
                directory = subelement.text
                print 'Directory: '+directory
            elif subelement.tag.lower() in ['license','licence']:
                license = subelement.text
                print 'License: '+license
            elif subelement.tag.lower() == 'maintainer':
                maintainer = subelement.text
                print 'Maintainer: '+maintainer
            elif subelement.tag.lower() == 'name':
                name = subelement.text
                print 'Name: '+name
            elif subelement.tag.lower() == 'price':
                currency = ""
                for attr, value in subelement.items():
                    if attr == 'currency':
                        currency = value
                    #endif
                #endfor
                price = subelement.text+currency
                print 'Price: '+price
            elif subelement.tag.lower() == 'programming_languages' or subelement.tag.lower() == 'programminglanguages':
                programming_languages = subelement.text
                print 'Programming languages: '+programming_languages
            elif subelement.tag.lower() == 'purpose':
                purpose = subelement.text
                print 'Purpose: '+purpose
            elif subelement.tag.lower() == 'system_variables' or subelement.tag.lower() == 'systemvariables':
                system_variables = subelement.text
                print 'System variables: '+system_variables
            elif subelement.tag.lower() == 'territories':
                territories = subelement.text
                print 'Territories: '+territories
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            elif subelement.tag.lower() == 'version':
                version = subelement.text
                print 'Version: '+version
            #endif
        #endfor
        if name:
            newDocument = {}
            newDocument['application_name'] = name
            newDocument['author'] = author
            newDocument['copyright'] = copyright
            newDocument['description'] = description
            newDocument['license'] = license
            newDocument['maintainer'] = maintainer
            newDocument['application_date'] = date
            newDocument['application_directory'] = directory
            newDocument['price'] = price
            newDocument['developer'] = developer
            newDocument['application_version'] = version
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef

    def process_riscos_xml_fonts_element(self, parent_url, fontsElement):
        print 'Processing '+fontsElement.tag+'...'
        for subelement in fontsElement.iter():
            if subelement.tag.lower() == 'font':
                self.process_riscos_xml_font_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_font_element(self, parent_url, fontElement):
        epoch = int(time.time())
        font = ""
        url = ""
        print 'Processing '+fontElement.tag+'...'
        #xmlcode = etree.tostring(fontElement)
        #print xmlcode
        for subelement in fontElement.iter():
            if subelement.tag.lower() == 'name':
                font = subelement.text
                print 'Font: '+font
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if font and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['font'] = [font]
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef    
    
    def process_riscos_xml_modules_element(self, parent_url, modulesElement):
        print 'Processing '+modulesElement.tag+'...'
        for subelement in modulesElement.iter():
            if subelement.tag.lower() in ['module','relocatablemodule'] or subelement.tag.lower() == 'relocatable_module':
                self.process_riscos_xml_module_element(parent_url, subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_module_element(self, parent_url, moduleElement):
        epoch = int(time.time())
        addressingMode = ""
        module = ""
        url = ""
        version = ""
        print 'Processing '+moduleElement.tag+'...'
        #xmlcode = etree.tostring(moduleElement)
        #print xmlcode
        for subelement in moduleElement.iter():
            if subelement.tag.lower() == 'addressing_mode':
                addressingMode = subelement.text
                print 'Addressing mode: '+addressingMode
            elif subelement.tag.lower() == 'name':
                module = subelement.text
                print 'Module: '+module
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            elif subelement.tag.lower() == 'version':
                version = subelement.text
                print 'Version: '+version
            #endif
        #endfor
        if module and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            subDocument = {}
            subDocument['name'] = module
            if version:
                subDocument['version'] = version
            #endif
            if addressingMode:
                subDocument['addressing_mode'] = addressingMode
            #endif
            newDocument['relocatable_modules'] = [subDocument]
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef
    
    def process_riscos_xml_monitor_definition_files_element(self, parent_url, monitorDefinitionFilesElement):
        print 'Processing '+monitorDefinitionFilesElement.tag+'...'
        for subelement in monitorDefinitionFilesElement.iter():
            if subelement.tag.lower() in ['monitordefinitionfile','monitor_definition_file','mdf']:
                self.process_riscos_xml_monitor_definition_file_element(parent_url, subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_monitor_definition_file_element(self, parent_url, monitorDefinitionFileElement):
        epoch = int(time.time())
        monitor = ""
        url = ""
        print 'Processing '+monitorDefinitionFileElement.tag+'...'
        #xmlcode = etree.tostring(monitorDefinitionFileElement)
        #print xmlcode
        for subelement in monitorDefinitionFileElement.iter():
            if subelement.tag.lower() == 'monitor':
                monitor = subelement.text
                print 'Monitor: '+monitor
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if monitor and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['monitor_definition_files'] = [monitor]
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef
    
    def process_riscos_xml_printer_definition_files_element(self, parent_url, printerDefinitionFilesElement):
        print 'Processing '+printerDefinitionFilesElement.tag+'...'
        for subelement in printerDefinitionFilesElement.iter():
            if subelement.tag.lower() in ['printer_definition_file','printerdefinitionfile','pdf']:
                self.process_riscos_xml_printer_definition_file_element(parent_url, subelement)
            #endif
        #endfor         
    #enddef
    
    def process_riscos_xml_printer_definition_file_element(self, parent_url, printerDefinitionFileElement):
        epoch = int(time.time())
        printer = ""
        url = ""
        print 'Processing '+printerDefinitionFileElement.tag+'...'
        #xmlcode = etree.tostring(printerDefinitionFileElement)
        #print xmlcode
        for subelement in printerDefinitionFileElement.iter():
            if subelement.tag.lower() == 'printer':
                printer = subelement.text
                print 'Printer: '+printer
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if printer and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['printer_definition_files'] = [printer]
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef

    def process_riscos_xml_utilities_element(self, parent_url, utilitiesElement):
        print 'Processing '+utilitiesElement.tag+'...'
        for subelement in utilitiesElement.iter():
            if subelement.tag.lower() == 'utility':
                self.process_riscos_xml_utility_element(parent_url, subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_utility_element(self, parent_url, utilityElement):
        epoch = int(time.time())
        utility = ""
        url = ""
        version = ""
        print 'Processing '+utilityElement.tag+'...'
        #xmlcode = etree.tostring(utilityElement)
        #print xmlcode
        for subelement in utilityElement.iter():
            if subelement.tag.lower() == 'name':
                utility = subelement.text
                print 'Utility: '+utility
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            elif subelement.tag.lower() == 'version':
                version = subelement.text
                print 'Version: '+version
            #endif
        #endfor
        if utility and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            if version:
                newDocument['utilities'] = [{'name':utility,'version':version}]
            else:
                newDocument['utilities'] = [{'name':utility}]
            #endif
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef    
    
    def process_riscos_xml_glossary_element(self, parent_url, glossaryElement):
        print 'Processing '+glossaryElement.tag+'...'
        #xmlcode = etree.tostring(glossaryElement)
        #print xmlcode
        for subelement in glossaryElement.iter():
            if subelement.tag.lower() == 'entry':
                self.process_riscos_xml_entry_element(parent_url, subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_entry_element(self, parent_url, entryElement):
        epoch = int(time.time())
        term = ""
        definition = ""
        print 'Processing '+entryElement.tag+'...'
        #xmlcode = etree.tostring(entryElement)
        #print xmlcode
        for subelement in entryElement.iter():
            if subelement.tag.lower() == 'term':
                term = subelement.text
                print 'Term: '+term
            elif subelement.tag.lower() == 'definition':
                definition = subelement.text
                print 'Definition: '+definition
            #endif
        #endfor
        if term and definition:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['parent_url'] = parent_url
            newDocument['glossary_term'] = term
            newDocument['glossary_definition'] = definition
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef

    def process_riscos_xml_usergroups_element(self, parent_url, usergroupsElement):
        print 'Processing '+usergroupsElement.tag+'...'
        for subelement in usergroupsElement.iter():
            if subelement.tag.lower() in ['usergroup','user_group']:
                self.process_riscos_xml_usergroup_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_usergroup_element(self, parent_url, usergroupElement):
        epoch = int(time.time())
        usergroup = ""
        address = ""
        description = ""
        email = ""
        telephone = ""
        url = ""
        print 'Processing '+fontElement.tag+'...'
        #xmlcode = etree.tostring(fontElement)
        #print xmlcode
        for subelement in fontElement.iter():
            if subelement.tag.lower() == 'address':
                address = subelement.text
                print 'Address: '+address
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
            elif subelement.tag.lower() == 'email':
                email = subelement.text
                print 'Email: '+email    
            elif subelement.tag.lower() == 'name':
                usergroup = subelement.text
                print 'User group: '+usergroup
            elif subelement.tag.lower() == 'telephone':
                telephone = subelement.text
                print 'Telephone: '+telephone
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if developer and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['user_group'] = usergroup
            newDocument['address'] = address
            newDocument['description'] = description
            newDocument['email'] = email
            newDocument['telephone'] = telephone
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef 

    def process_riscos_xml_videos_element(self, parent_url, videosElement):
        print 'Processing '+videosElement.tag+'...'
        for subelement in videosElement.iter():
            if subelement.tag.lower() == 'video':
                self.process_riscos_xml_video_element(parent_url, subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_video_element(self, parent_url, videoElement):
        epoch = int(time.time())
        video = ""
        description = ""
        url = ""
        print 'Processing '+videoElement.tag+'...'
        #xmlcode = etree.tostring(videoElement)
        #print xmlcode
        for subelement in videoElement.iter():
            if subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description   
            elif subelement.tag.lower() == 'title':
                video = subelement.text
                print 'Video: '+video
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
            #endif
        #endfor
        if developer and url:
            newDocument = {}
            newDocument['riscos_xml'] = parent_url
            newDocument['url'] = url
            newDocument['parent_url'] = parent_url
            newDocument['video'] = video
            newDocument['description'] = description
            newDocument['last_scanned'] = epoch
            newDocument['next_scan'] = epoch + self.periodYear
            self.riscosCollection.insert(newDocument)
        #endif
    #enddef
    
    def analyse_rss_feed(self, url, data):
        epoch = int(time.time())
        data = data.replace('\n','')
        data = data.replace('\r','')
        if re.search('<rss(.*?)</rss>',data):
            channelPattern = re.compile('<channel>(.*?)</channel>')
            itemPattern = re.compile('<item>(.*?)</item>')
            titlePattern = re.compile('<title>(.*?)</title>')
            linkPattern = re.compile('<link>(.*?)</link>')
            descriptionPattern = re.compile('<description>(.*?)</description>')
            channels = channelPattern.findall(data)
            for channel in channels:
                itemResults = itemPattern.findall(channel)
                if itemResults:
                    for itemResult in itemResults:
                        titleResults = titlePattern.findall(itemResult)
                        linkResults = linkPattern.findall(itemResult)
                        descriptionResults = descriptionPattern.findall(itemResult)
                        if titleResults and linkResults:
                            newDocument = {}
                            newDocument['url'] = url
                            newDocument['rss_feed'] = url
                            newDocument['rss_feed_item_date'] = epoch
                            newDocument['rss_feed_item_title'] = titleResults[0]
                            if descriptionResults:
                                newDocument['rss_feed_item_description'] = descriptionResults[0]
                            #endif
                            newDocument['rss_feed_item_link'] = linkResults[0]
                            newDocument['last_scanned'] = epoch
                            newDocument['next_scan'] = epoch + self.periodMonth
                            self.riscosCollection.insert(newDocument)
                            if not self.url_in_riscos(linkResults[0]) and not self.url_in_urls(linkResults[0]) and not self.url_in_rejects(linkResults[0]) and not self.url_in_reserves(linkResults[0]) and not self.suspended_url(linkResults[0]) and not self.blacklisted_url(linkResults[0]):
                                newDocument = {}
                                newDocument['url'] = linkResults[0]
                                if linkResults[0].lower().endswith('.zip') or linkResults[0].lower().__contains__('.zip?'):
                                    newDocument['zip_file'] = linkResults[0]
                                    newDocument['last_scanned'] = 0
                                else:
                                    newDocument['last_scanned'] = 1
                                #endif
                                newDocument['next_scan'] = epoch
                                self.urlsCollection.insert(newDocument)
                                print "Inserting into urls: "+newDocument['url']                      
                            #endif
                            print "Inserting into riscos: "+titleResults[0]
                        #endif
                    #endfor
                #endif
            #endfor
        #endif
    #enddef
    
    def url_pre_validation(self, document, data):
        valid = True
        if document['domain'] == 'www.ebay.co.uk':
            if document.has_key('page_title') and document['page_title']:
                if not self.page_riscos_related(document['page_title']):
                    valid = False
                #endif
            #endif
        if document['domain'] == 'www.thedownloadplanet.com':
            if not data.__contains__('<a href="/platform/risc-os/">RISC OS</a>'):
                valid = False
            #endif
        elif document['domain'] == 'web.archive.org':
            results = self.archivedUrlPattern.findall(document['url'])
            if results:
                if self.url_in_riscos(results[0]):
                    valid = False
                else:
                    if self.url_in_urls(results[0]):
                        if not self.url_in_reserves(document['url']):
                            print 'Moving Archive to Reserves '+document['url']+'...'
                            newDocument = {}
                            newDocument['url'] = document['url']
                            self.reservesCollection.insert(newDocument)
                        #endif
                        valid = False
                    #endif
                #endif
            #endif
        #endif
        return valid
    #enddef
    
    def url_post_validation(self, url, data):
        valid = True
        if url.__contains__('www.ebay.co.uk') and data.__contains__('The item you searched for is no longer available.'):
            valid = False
        #endif
        return valid
    #enddef
    
    def page_riscos_related(self, data):
        pageRiscosRelated = False
        for searchTerm in ['RISC OS','RISC&nbsp;OS','RISC-OS','RISCOS','RiscOS','risc os','risc-os','riscos','Archimedes','RiscPC','Qercus','Iyonix','Risc PC','Acorn Computer','riscpkg']:
            if data.__contains__(searchTerm):
                pageRiscosRelated = True
                break
            #endif
        #endfor
        return pageRiscosRelated
    #enddef
    
    def update_apps(self, url, document, apps):
        epoch = int(time.time())
        for [absolutes,appDate,appDir,appName,appVer,author,categories,copyright,description,dtpFormats,filetypesRead,filetypesSet,fonts,help,license,maintainer,minOsVers,monitorDefinitionFiles,packageName,packageSection,packageVersion,printerDefinitionFiles,priority,programmingLanguages,relocatableModules,relocatableModulesDependantUpon,source,territories,starCommands,systemVariables,toolboxRequired,utilities] in apps:
            existingDocument = ""
            if appDir:
                existingDocument = self.riscosCollection.find_one({'url':url,'application_directory':appDir})
            #endif
            if existingDocument:
                existingDocument['zip_file'] = url
                existingDocument['last_scanned'] = epoch
                existingDocument['next_scan'] = epoch + self.periodYear
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
                if document.has_key('parent_url') and document['parent_url']:
                    subDocument['parent_url'] = document['parent_url']
                #endif
                subDocument['zip_file'] = url
                subDocument['last_scanned'] = epoch
                subDocument['next_scan'] = epoch + self.periodYear
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
                    print "Inserting into riscos: "+subDocument['url']
                except:
                    True
            #endif
        #endfor
    #enddef   
    
    def analyse_zip_file(self, data):
        apps = []
        if data:
            hashData = hashlib.md5(data).hexdigest()
            path = self.path
            op = open(path+os.sep+'temp'+os.sep+hashData,'wb')
            op.write(data)
            op.close()
            hashDataPath = path+os.sep+'temp'+os.sep+hashData
            if os.path.exists(hashDataPath):
                if zipfile.is_zipfile(hashDataPath):
                    z = zipfile.ZipFile(hashDataPath, mode="r")
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
                                if moduleName.lower() != '!runimage':
                                    try:
                                        contents = z.read(object)
                                        addressingMode = ""
                                        moduleFlags = ord(contents[0x0030])
                                        if moduleFlags&1 == 1:
                                            addressingMode = '32-bit'
                                        elif moduleFlags&1 == 0:
                                            addressingMode = '26-bit'
                                        #endif
                                        results = self.moduleVersionPattern.findall(contents)
                                        if results != []:
                                            if addressingMode:
                                                relocatableModules.append({'name':moduleName,'version':results[0],'addressing_mode':addressingMode})
                                            else:
                                                relocatableModules.append({'name':moduleName,'version':results[0]})
                                            #endif
                                        else:
                                            if addressingMode:
                                                relocatableModules.append({'name':moduleName,'addressing_mode':addressingMode})
                                            else:
                                                relocatableModules.append({'name':moduleName})
                                            #endif
                                        #endif
                                    except:
                                        True
                                #endif
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
                                    name = encodedUtility
                                    version = ""
                                    syntax = ""
                                    if results != []:
                                        version = results[0]
                                    #endif
                                    results = self.utilitySyntaxPattern.findall(contents)
                                    if results != []:
                                         syntax = results[1]
                                    #endif
                                    if name and version and syntax:
                                        if not {'name':name,'version':version,'syntax':syntax} in utilities:
                                            utilities.append({'name':name,'version':version,'syntax':syntax})
                                        #endif
                                    elif name and version:
                                        if not {'name':name,'version':version} in utilities:
                                            utilities.append({'name':name,'version':version})
                                        #endif
                                    elif name:
                                        if not {'name':name} in utilities:
                                            utilities.append({'name':name})
                                        #endif                                    
                                    #endif
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
                                                modifiedObject = object.replace('/','.')
                                                if not modifiedObject in monitorDefinitionFiles:
                                                    monitorDefinitionFiles.append(modifiedObject)
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
                                    contents = ""
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

                                try:
                                    contents = z.read(object)
                                except:
                                    contents = ""

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
                                        if result.lower() != "run$path" and not result in systemVariables:
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
            try:
                os.remove(hashDataPath)
            except:
                True
        #endif
        return apps
    #enddef
#endclass

socket.setdefaulttimeout(30)

if __name__ == '__main__':
    riscosspider = riscosspider()
    riscosspider.continuous()
