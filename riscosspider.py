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
    
        # Connect to 'quarantine' collection
        self.quarantineCollection = db['quarantine']    
    
        self.housekeepingTasksLastRan = []
    
        self.months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    
        self.mirror = 'www.shalfield.com/riscos'
        self.mirrors = ['84.92.157.78/riscos','www.shalfield.com/riscos','192.168.88.1:8081/riscos']
    
        self.searchableAttributes = [
                                     ('Absolutes','absolutes'),
                                     ('Directory','directory'),
                                     ('Application Name','application_name'),
                                     ('Application Version','application_version'),
                                     ('ARC File','arc_file'),
                                     ('ARM Architectures','arm_architectures'),
                                     ('Authors','authors'),
                                     ('Book','book'),
                                     ('Categories','categories'),
                                     ('Computer','computer'),
                                     ('Contact','contact'),
                                     ('Copyright','copyright'),
                                     ('Date','date'),
                                     ('Dealer','dealer'),
                                     ('Description','description'),
                                     ('Developer','developer'),
                                     ('DTP Formats','dtp_formats'),
                                     ('Event','event',),
                                     ('FAQ','question'),
                                     ('Filetypes Run','filetypes_run'),
                                     ('Filetypes Set','filetypes_set'),
                                     ('Fonts','fonts'),
                                     ('Forum','forum'),
                                     ('Glossary Term','glossary_term'),
                                     ('Glossary Definition','glossary_definition'),
                                     ('Help','help'),
                                     ('How-To','howto'),
                                     ('Identifier','identifier'),
                                     ('licence','licence'),
                                     ('Magazine','magazine'),
                                     ('Maintainer','maintainer'),
                                     ('Module Dependencies','module_dependencies'),
                                     ('Monitor Definition Files','monitor_definition_files'),
                                     ('Package Name','package_name'),
                                     ('Package Section','package_section'),
                                     ('Package Version','package_version'),
                                     ('Page Title','page_title'),
                                     ('Podule','podule'),
                                     ('Portable Document Format File','pdf_file'),
                                     ('Pricing','pricing'),
                                     ('Printer Definition Files','printer_definition_files'),
                                     ('Priority','priority'),
                                     ('Programming Languages','programming_languages'),
                                     ('Project','project'),
                                     ('Provider','provider'),
                                     ('Publisher','publisher'),
                                     ('Purpose','purpose'),
                                     ('Relocatable Modules','relocatable_modules'),
                                     ('RISC OS Versions','riscos_versions'),
                                     ('* Command','star_command'),
                                     ('Source','source'),
                                     ('Spark File','spark_file'),
                                     ('Syndicated Feed','syndicated_feed'),
                                     ('Syndicated Feed Item Description','syndicated_feed_item_description'),
                                     ('Syndicated Feed Item Title','syndicated_feed_item_title'),
                                     ('System Variables','system_variables'),
                                     ('Territories','territories'),
                                     ('User Group','user_group'),
                                     ('Utilities','utilities'),
                                     ('Video','video'),
                                     ('ZIP File','zip_file')
                                     ]
        
        if self.riscosCollection.find({}).count() == 0 and self.urlsCollection.find({}).count() == 0:
            for url in ['http://www.riscosopen.org/']:
                self.insert_url_into_urls(url, "", 0, epoch, False, False, True)
            #endfor
        #endif       
        
        self.trusted_domains = {}
        
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

        self.blacklisted_domains = {}
        self.blacklisted_domains['edit.yahoo.com'] = ''
        self.blacklisted_domains['validator.w3.org'] = ''
        
        self.suspension = ['yahooshopping.pgpartner.com',
                           'shopping.yahoo.com',
                           'www.riscosopen.org/viewer/view/'
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
        epoch = int(time.time())
        print "Spidering has started..."
        syndicatedFeedTimer = 0
        while True:
            hour = time.localtime()[3]
            if (hour >= 6 and hour <= 22):
                print "Performing housekeeping..."
                self.housekeeping()
            #endif
            if syndicatedFeedTimer == 0 or syndicatedFeedTimer+self.periodDay < epoch:
                self.read_syndicated_feeds()
                syndicatedFeedTimer = epoch
            #endif            
            print "Spidering is running..."
            latestMessage = self.spider()
            print latestMessage            
        #endwhile
        print "Spidering has finished!"
    #enddef

    def read_syndicated_feeds(self):
        for collection in [self.riscosCollection,self.urlsCollection]:
            syndicatedFeeds = collection.find({'syndicated_feed':{'$exists':True,'$ne':['']}}).distinct('syndicated_feed')
            for syndicatedFeed in syndicatedFeeds:
                req = urllib2.Request(syndicatedFeed)
                req.add_unredirected_header('User-Agent', 'RISC OS Search Engine http://'+self.mirror)
                try:
                    urlp = urllib2.urlopen(req)
                    data = urlp.read()
                    urlp.close()
                    for document in collection.find({'syndicated_feed':syndicatedFeed}):
                        collection.remove({'_id':ObjectId(document['_id'])})
                    #endfor
                    if re.search('</rss>',data):
                        self.analyse_rss_feed(syndicatedFeed, data)
                    elif re.search('</feed>',data):
                        self.analyse_atom_feed(syndicatedFeed, data)
                    #endif
                except:
                    True
            #endfor
        #endfor
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
            if self.blacklisted_domains.has_key(netloc):
                for blacklistedDocument in self.urlsCollection.find({'domain':netloc,'_id':{'$ne':ObjectId(document['_id'])}}):
                    print 'Removing Blacklisted URL '+blacklistedDocument['url']+'...'
                    self.urlsCollection.remove({'_id':ObjectId(blacklistedDocument['_id'])})
                #endfor
                return True
            elif self.blacklisted_domains.has_key(netloc+'/'+path):
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
            if self.blacklisted_domains.has_key(netloc) or self.blacklisted_domains.has_key(netloc+'/'+path):
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
                if self.urlsCollection.find({'url':document['url']}).count() > 1:
                    print "Removing duplicate from urls: "+document['url']
                    self.urlsCollection.remove({'_id':ObjectId(document['_id'])})
                #endif
            #endfor
        except:
            True
    #enddef 
    
    def identify_superseded_applications(self):
        for document in self.riscosCollection.find({'directory':{'$ne':''},'application_version':{'$ne':''}}):
            try:
                selectedVersion = float(document['application_version'])
                highestVersion = selectedVersion
                otherVersions = self.riscosCollection.find({'directory':document['directory'],'application_version':{'$ne':['',document['application_version']]}}).distinct('application_version')
                for otherVersion in otherVersions:
                    try:
                        if float(otherVersion) > highestVersion:
                            highestVersion = float(otherVersion)
                        #endif
                    except:
                        True
                #endfor
                if highestVersion > selectedVersion:
                    for otherDocument in self.riscosCollection.find({'directory':document['directory'],'application_version':str(highestVersion)}):
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
    
    def url_in_a_collection(self, url):
        if self.url_in_riscos(url) or self.url_in_urls(url) or self.url_in_rejects(url) or self.url_in_quarantine(url) or self.url_in_reserves(url):
            return True
        else:
            return False
        #endif
    #enddef
    
    def url_in_riscos(self, url):
        if self.riscosCollection.find({'url':url,'syndicated_feed':{'$exists':False}}).count():
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
    
    def url_in_quarantine(self, url):
        if self.quarantineCollection.find({'url':url}).count():
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
        noOfTasks = 18
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
                        if not self.url_in_a_collection(line) and not self.suspended_url(line) and not self.blacklisted_url(line):
                            self.insert_url_into_urls(line, "", 0, epoch, False, False, False)
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
                elif document.has_key('riscos_xml') and document['riscos_xml']:
                    continue
                elif document.has_key('syndicated_feed') and document['syndicated_feed']:
                    continue
                else:
                    print "Removing document with no url from riscos"
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
            urlsCount = self.urlsCollection.find({}).count()
            riscosCount = self.riscosCollection.find({}).count()
            if urlsCount < riscosCount:
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
                                print str(counter)+' of '+str(total)+' : Moving from riscos to urls: '+movedDocument['url']
                                parent_url = ""
                                syndicated_feed = False
                                if document.has_key('parent_url') and document['parent_url']:
                                    parent_url = document['parent_url']
                                #endif
                                if document.has_key('syndicated_feed') and document['syndicated_feed']:
                                    syndicated_feed = True
                                #endif
                                self.insert_url_into_urls(normalisedUrl, parent_url, 0, 0, syndicated_feed, False, False)
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
                for document in collection.find({'url':{'$exists':True,'$ne':''}}):
                    if document.has_key('url') and document['url']:
                        if not self.valid_hyperlink_filetype(document['url']):
                            self.insert_url_into_rejects(document['url'])
                            print "Removing: "+document['url']
                            collection.remove({'_id':ObjectId(document['_id'])})
                        #endif
                    #endif
                #endfor
            #endfor
        elif selection == 9:
            print str(selection)+": Removing duplicate riscos documents"
            self.remove_riscos_duplicates()
        elif selection == 10:
            print str(selection)+": Removing duplicate urls documents"
            self.remove_urls_duplicates()
        elif selection == 11:
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
            print str(selection)+": Identify riscos.xml and .zip files"
            for document in self.urlsCollection.find({'url':{'$ne':['']}}):
                if document.has_key('url') and document['url']:
                    if document['url'].endswith('/riscos.xml'):
                        document['riscos_xml'] = document['url']
                        self.urlsCollection.save(document)
                    elif document['url'].lower().endswith('.zip') or document['url'].lower().__contains__('.zip?'):
                        document['zip_file'] = document['url']
                        self.urlsCollection.save(document)
                    #endif
                #endif
            #endfor
        elif selection == 16:
            print str(selection)+": Move documents whose next_scan value is lower than epoch"
            try:
                total = self.riscosCollection.find({'url':{'$ne':['']},'next_scan':{'$lt':epoch}}).count()
                counter = 0
                for document in self.riscosCollection.find({'url':{'$ne':['']},'next_scan':{'$lt':epoch}}):
                    if document['url'].startswith('/'):
                        print 'Ignoring '+document['url']
                    else:
                        counter += 1
                        if (document.has_key('riscos_xml') and document['riscos_xml']) or (document.has_key('syndicated_feed') and document['syndicated_feed']):
                            normalisedUrl = self.normalise_url(document['parent_url'])
                        else:
                            normalisedUrl = self.normalise_url(document['url'])
                        #endif
                        if not self.url_in_urls(normalisedUrl):
                            print str(counter)+' of '+str(total)+' : Moving from riscos to urls: '+normalisedUrl
                            parent_url = ""
                            syndicated_feed = False
                            riscos_xml = False
                            if document.has_key('riscos_xml') and document['riscos_xml']:
                                riscos_xml = True                               
                            elif document.has_key('syndicated_feed') and document['syndicated_feed']:
                                syndicated_feed = True
                            elif document.has_key('parent_url') and document['parent_url']:
                                parent_url = document['parent_url']                           
                            #endif
                            self.insert_url_into_urls(normalisedUrl, parent_url, 0, 0, syndicated_feed, riscos_xml, False)
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
        elif selection == 17:
            print str(selection)+": Backup MongoDB database"
            localTime = time.localtime(int(time.time()))
            year = str(localTime[0])
            month = str(localTime[1])
            if len(month) == 1:
                month = '0'+month
            #endif
            day = str(localTime[2])
            if len(day) == 1:
                day = '0'+day
            #endif
            if not os.path.exists(self.path+os.sep+'dbdump'+os.sep+year+month+day):
                os.mkdir(self.path+os.sep+'dbdump'+os.sep+year+month+day)
                port = ""
                if self.mongodbPort != 27017:
                    port = ' --port '+str(self.mongodbPort)
                #endif
                executable = r'"C:\Program Files\MongoDB\bin\mongodump.exe" --verbose'+port+' --db riscos --out '+self.path+os.sep+'dbdump'+os.sep+year+month+day
                (status,output) = self.getstatusoutput(executable)
            #endif                
        #endif
        self.housekeepingTasksLastRan[selection] = int(time.time())
    #enddef
    
    def getstatusoutput(self,cmd):
        """Return (status, output) of executing cmd in a shell."""
        mswindows = (sys.platform == "win32")
        if not mswindows:
            cmd = '{ ' + cmd + '; }'
        #endif
        pipe = os.popen(cmd + ' 2>&1', 'r')
        text = pipe.read()
        sts = pipe.close()
        if sts is None: sts = 0
        if text[-1:] == '\n': text = text[:-1]
        return sts, text
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
        lastModified = ""
        latestMessage = ""
        epoch = int(time.time())
        
        # Update any database keys whose name has been altered
        changedAttributes = [('syndicated_feed_item_date','date')]
        if changedAttributes:
            for (oldAttribute,newAttribute) in changedAttributes:
                for document in self.riscosCollection.find({oldAttribute:{'$exists':True}}):
                    document[newAttribute] = document[oldAttribute]
                    del document[oldAttribute]
                    self.riscosCollection.save(document)
                #endfor
            #endfor
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
        
        # Find a non-indexed document with a .zip-based URL
        if not url:
            for document in self.urlsCollection.find({'zip_file':{'$exists':True}}):
                if document.has_key('url') and document['url']:
                    if not document.has_key('last_scanned') or (document.has_key('last_scanned') and document['last_scanned'] < epoch-self.periodWeek):
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
            #endfor
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
        
        # Attempt to find a syndicated feed directly
        if not url:
            doc_ids = self.urlsCollection.find({'syndicated_feed':{'$exists':True}}).distinct('_id')
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
        
        # Attempt to find a syndicated feed indirectly
        if not url:
            searchCriteria = {}
            searchCriteria['url'] = re.compile('(?i)(?:atom|rss|xml|feeds?)')
            for document in self.urlsCollection.find(searchCriteria):
                if document.has_key('url') and document['url']:
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

        # Attempt to find a possible syndicated feed indirectly
        if not url:
            searchCriteria = {}
            searchCriteria['url'] = re.compile('(?i)(?:atom|rss)')
            for document in self.urlsCollection.find(searchCriteria):
                if document.has_key('url') and document['url']:
                    if document['url'].lower().__contains__('atom') or document['url'].lower().__contains__('rss'):
                        url = document['url']
                        print "Processing [7] "+url+'...'
                    #endif
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
                    print "Processing [8] "+url+'...'
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
                        print "Processing [9] "+url+'...'
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
                    print "Processing [10] "+url+'...'
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
            self.insert_url_into_rejects(url)
            self.urlsCollection.remove({'url':url})
            print 'Removing from urls: '+url
            latestMessage = 'A possible IPv6 url at '+url+', so duly removed!'
            return latestMessage
        #endtryexcept

        document['url'] = url
        
        if not scheme or not netloc:
            self.insert_url_into_rejects(document['url'])
            self.urlsCollection.remove({'url':document['url']})
            print 'Removing from urls: '+document['url']
            latestMessage = 'Incomplete URL, so duly removed'
            return latestMessage
        #endif        

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
                self.insert_url_into_rejects(document['url'])
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url          
                latestMessage = 'Disallowed access to <a href="'+url+'">'+url+'</a> due to robots.txt!'
                
                try:
                    for document in self.urlsCollection.find({'url':{"$exists":True,"$ne":""}}):
                        if document.has_key('url') and document['url']:
                            try:
                                (altScheme,altNetloc,altPath,altQuery,altFragment) = urlparse.urlsplit(document['url'])
                                if altPath == path and altNetloc == netloc and  altScheme == scheme:
                                    self.insert_url_into_rejects(document['url'])
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
        except socket.error:
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
            document['next_scan'] = epoch + self.periodWeek
            self.urlsCollection.save(document)
            latestMessage = 'We have suffered a socket timeout whilst trying to reach <a href="'+url+'">'+url+'</a> so will try again later!'
            return latestMessage
        except SSLError:
            # The read operation timed out
            if document.has_key('seed') and document['seed'] == True:
                latestMessage = 'Unable to reach <a href="'+url+'">'+url+'</a> so will try again later!'
                return latestMessage
            else:
                if self.lastSuccessfulInternetConnection >= epoch-60:
                    self.insert_url_into_rejects(document['url'])
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> is unreachable so it has now been removed!'
                else:
                    if document.has_key('strikes'):
                        if document['strikes'] >= 2:
                            #if self.lastSuccessfulInternetConnection >= epoch-60:
                            self.insert_url_into_rejects(url)
                            self.urlsCollection.remove({'url':url})
                            print 'Removing from urls: '+url
                            latestMessage = 'Three strikes raised against <a href="'+url+'">'+url+'</a> so it has now been removed!'
                            ##endif
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
                self.insert_url_into_rejects(url)
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
                self.insert_url_into_rejects(url)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Bad url, '+url+', so duly removed!'
                return latestMessage
            #endif
        except socket.error:
            if self.lastSuccessfulInternetConnection >= epoch-60:
                self.insert_url_into_rejects(url)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Bad url, '+url+', so duly removed!'
                return latestMessage
            #endif
        except httplib.InvalidURL:
            if self.lastSuccessfulInternetConnection >= epoch-60:
                self.insert_url_into_rejects(url)
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
                    self.insert_url_into_rejects(url)
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> is unreachable so it has now been removed!'
                    return latestMessage
                else:
                    if document.has_key('strikes'):
                        if document['strikes'] >= 2:
                            #if self.lastSuccessfulInternetConnection >= epoch-60:
                            self.insert_url_into_rejects(url)
                            self.urlsCollection.remove({'url':url})
                            print 'Removing from urls: '+url
                            latestMessage = 'Three strikes raised against <a href="'+url+'">'+url+'</a> so it has now been removed!'
                            return latestMessage
                            ##endif
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
            self.insert_url_into_rejects(url)        
            self.urlsCollection.remove({'url':url})
            print 'Removing from urls: '+url
            latestMessage = 'Although <a href="'+url+'">'+url+'</a> was successfully read, no data was returned'
            return latestMessage          
        else:
            metaRobotsResults = self.metaRobotsPattern.findall(data)
            if metaRobotsResults and metaRobotsResults[0].__contains__('noindex'):
                self.insert_url_into_rejects(url)        
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Although <a href="'+url+'">'+url+'</a> was successfully read, indexing is disallowed'
                return latestMessage
            #endif
        
            if urlp.headers.has_key('last-modified') and urlp.headers['last-modified']:
                rawLastModified = urlp.headers['last-modified']
                lastModified = int(time.mktime(time.strptime(rawLastModified[5:25],"%d %b %Y %H:%M:%S")))
            #endif
        
            if url.lower().endswith('.arc'):
                print 'Analysing '+url+' as Archive file...'
                newDocument = {}
                newDocument['url'] = url
                newDocument['arc_file'] = url
                newDocument['last_scanned'] = epoch
                newDocument['next_scan'] = epoch + self.periodYear
                if newDocument.has_key('strike'):
                    del newDocument['strike']
                #endif
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
                if newDocument.has_key('strike'):
                    del newDocument['strike']
                #endif                
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
                if newDocument.has_key('strike'):
                    del newDocument['strike']
                #endif
                self.riscosCollection.insert(newDocument)
                print "Inserting into riscos: "+newDocument['url']
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, a Portable Document Format file'
                return latestMessage
            elif url.lower().endswith('/riscos.xml') and re.search('</riscos>',data):
                print 'Processing '+url+' as riscos.xml file...'
                self.process_riscos_xml_file(url, data, lastModified)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, a riscos.xml file'
                return latestMessage
            elif url.lower().endswith('.rss') or re.search('</rss>',data):
                print 'Analysing '+url+' as RSS feed...'
                self.analyse_rss_feed(url, data)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, an RSS Feed'
                return latestMessage
            elif url.lower().endswith('.atom') or re.search('</feed>',data):
                print 'Analysing '+url+' as Atom feed...'
                self.analyse_atom_feed(url, data)
                self.urlsCollection.remove({'url':url})
                print 'Removing from urls: '+url
                latestMessage = 'Found <a href="'+url+'">'+url+'</a>, an Atom Feed'
                return latestMessage
            elif url.lower().endswith('.zip') or url.lower().__contains__('.zip?'):
                print 'Analysing '+url+' as ZIP file...'
                try:
                    apps, latestMessage = self.analyse_zip_file(url, data)
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    if apps:
                        self.update_apps(url,document,apps)
                        latestMessage = 'Indexing <a href="'+url+'">'+url+'</a>'
                    else:
                        latestMessage = 'No applications to index within <a href="'+url+'">'+url+'</a>'
                        self.insert_url_into_rejects(url)
                    #endif
                    return latestMessage
                except zipfile.BadZipfile:
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'Bad zipfile encountered at <a href="'+url+'">'+url+'</a>'
                    return latestMessage               
            elif self.content_riscos_related(data):
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
                                if newDocument.has_key('strike'):
                                    del newDocument['strike']
                                #endif
                                self.riscosCollection.insert(newDocument)
                                print "Inserting into riscos: "+newDocument['url']
                            #endif
                        except:
                            True
                    #endif
                #endif
                
                if lastModified:
                    try:
                        document['last_scanned'] = epoch
                        document['next_scan'] = self.calculate_next_scan_time(lastModified, epoch)
                        document['date'] = lastModified
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
                            if not self.url_in_a_collection(result) and not self.suspended_url(result) and not self.blacklisted_url(result):
                                self.insert_url_into_urls(result, url, 1, 0, False, False, False)
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
                                    if not self.url_in_a_collection(result) and not self.suspended_url(result) and not self.blacklisted_url(result):
                                        self.insert_url_into_urls(result, url, 1, 0, False, False, False)
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
                    self.insert_url_into_rejects(url)
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> has been rejected as not RISC OS-related!'
                #endif
            #endif
        #endif
        return latestMessage
    #enddef    
    
    def insert_url_into_urls(self, url, parent_url="", last_scanned=0, next_scan=0, syndicated_feed=False, riscos_xml=False, seed=False):
        epoch = int(time.time())
        urlDocument = {}
        urlDocument['url'] = url
        if parent_url:
            urlDocument['parent_url'] = parent_url
        #endif
        if seed:
            urlDocument['seed'] = True
        #endif
        if url.lower().endswith('.zip') or url.lower().__contains__('.zip?'):
            urlDocument['zip_file'] = url
            urlDocument['last_scanned'] = 0
        elif riscos_xml or url.lower().endswith('/riscos.xml'):
            urlDocument['riscos_xml'] = url
        elif syndicated_feed:
            urlDocument['syndicated_feed'] = url
        elif seed:
            urlDocument['last_scanned'] = 0
        elif last_scanned:
            urlDocument['last_scanned'] = last_scanned
        else:
            urlDocument['last_scanned'] = 1
        #endif
        if next_scan:
            urlDocument['next_scan'] = next_scan
        else:
            urlDocument['next_scan'] = epoch
        #endif
        self.urlsCollection.insert(urlDocument)
        print 'Inserting into urls: '+url     
    #enddef
    
    def insert_url_into_rejects(self, url):
        epoch = int(time.time())
        rejectDocument = {}
        rejectDocument['url'] = url
        rejectDocument['last_scanned'] = epoch
        self.rejectsCollection.insert(rejectDocument)
        print 'Inserting into rejects: '+url     
    #enddef
    
    def riscos_xml_search(self,url):
        epoch = int(time.time())
        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
        riscos_xml_urls = [scheme+'://'+netloc+'/riscos.xml',scheme+'://'+netloc+'/'+path+'/riscos.xml']
        for riscos_xml_url in riscos_xml_urls:
            if not self.url_in_a_collection(riscos_xml_url) and not self.suspended_url(riscos_xml_url) and not self.blacklisted_url(riscos_xml_url):
                print 'Searching for '+url+'...'
                req = urllib2.Request(riscos_xml_url)
                req.add_unredirected_header('User-Agent', 'RISC OS Search Engine http://www.shalfield.com/riscos')
                found = True
                try:
                    urlp = urllib2.urlopen(req)
                    data = urlp.read()
                    urlp.close()
                    if data:
                        lastModified = ""
                        if urlp.headers.has_key('last-modified') and urlp.headers['last-modified']:
                            rawLastModified = urlp.headers['last-modified']
                            lastModified = int(time.mktime(time.strptime(rawLastModified[5:25],"%d %b %Y %H:%M:%S")))
                        #endif
                        self.process_riscos_xml_file(url,data,lastModified)     
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
                    self.insert_url_into_rejects(url)           
                #endif
                if found:
                    break
                #endif
            #endif
        #endfor
    #enddef
    
    def calculate_next_scan_time(self, lastModified, epoch):
        nextScan = epoch + self.periodYear
        timeSinceModified = epoch - lastModified
        if timeSinceModified < self.periodYear:
            nextScan = epoch + timeSinceModified
        #endif
        return nextScan
    #enddef
    
    def process_riscos_xml_file(self, parent_url, xmlcode, lastModified):
        for riscosXmlDocument in self.riscosCollection.find({'parent_url':parent_url}):
            print 'Removing riscos.xml entry for '+riscosXmlDocument['parent_url']+'...'
            self.riscosCollection.remove({'_id':ObjectId(riscosXmlDocument['_id'])})
        #endfor
        print 'Processing '+parent_url+'...'

        try:
            riscos = etree.XML(xmlcode)
            for subelement in riscos.iterchildren():
                print 'Processing tag: '+riscos.tag+' -> '+subelement.tag
                if subelement.tag == 'absolutes':
                    self.process_riscos_xml_absolutes_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'anniversaries':
                    self.process_riscos_xml_anniversaries_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'apps':
                    self.process_riscos_xml_apps_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'books':
                    self.process_riscos_xml_books_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'computers':
                    self.process_riscos_xml_computers_element(parent_url, subelement, lastModified)                    
                elif subelement.tag == 'dealers':
                    self.process_riscos_xml_dealers_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'developers':
                    self.process_riscos_xml_developers_element(parent_url, subelement, lastModified)
                elif subelement.tag.lower() == 'errormessages':
                    self.process_riscos_xml_errormessages_element(parent_url, subelement, lastModified)                    
                elif subelement.tag == 'events':
                    self.process_riscos_xml_events_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'faqs':
                    self.process_riscos_xml_faqs_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'fonts':
                    self.process_riscos_xml_fonts_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'forums':
                    self.process_riscos_xml_forums_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'glossary':
                    self.process_riscos_xml_glossary_element(parent_url, subelement, lastModified)
                elif subelement.tag.lower() == 'howtos':
                    self.process_riscos_xml_howtos_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'magazines':
                    self.process_riscos_xml_magazines_element(parent_url, subelement, lastModified)
                elif subelement.tag.lower() == 'monitordefinitionfiles':
                    self.process_riscos_xml_monitor_definition_files_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'peripherals':
                    self.process_riscos_xml_peripherals_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'podules':
                    self.process_riscos_xml_podules_element(parent_url, subelement, lastModified)
                elif subelement.tag.lower() == 'printerdefinitionfiles':
                    self.process_riscos_xml_printer_definition_files_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'projects':
                    self.process_riscos_xml_projects_element(parent_url, subelement, lastModified)
                elif subelement.tag.lower() == 'relocatablemodules':
                    self.process_riscos_xml_standalone_relocatable_modules_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'services':
                    self.process_riscos_xml_services_element(parent_url, subelement, lastModified)   
                elif subelement.tag.lower() == 'usergroups':
                    self.process_riscos_xml_usergroups_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'utilities':
                    self.process_riscos_xml_standalone_utilities_element(parent_url, subelement, lastModified)
                elif subelement.tag == 'videos':
                    self.process_riscos_xml_videos_element(parent_url, subelement, lastModified)
                else:
                    print "Unknown riscos.xml code: "+etree.tostring(subelement)         
                #endif
            #endfor
        except:
            print 'Error: Unable to parse riscos.xml file!'
    #enddef
    
    def process_riscos_xml_dealers_element(self, parent_url, dealersElement, lastModified):
        print 'Processing '+dealersElement.tag+'...'
        for subelement in dealersElement.iterchildren():
            print 'Processing tag: '+dealersElement.tag+' -> '+subelement.tag
            if subelement.tag == 'dealer':
                self.process_riscos_xml_dealer_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_dealer_element(self, parent_url, dealerElement, lastModified):
        newDocument = {}
        print 'Processing '+dealerElement.tag+'...'
        for subelement in dealerElement.iterchildren():
            print 'Processing tag: '+dealerElement.tag+' -> '+subelement.tag
            if subelement.tag in ['address','contact','email','telephone','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor               
            elif subelement.tag == 'name':
                dealer = subelement.text
                print 'Dealer: '+dealer
                newDocument['dealer'] = dealer
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 
    
    def process_riscos_xml_developers_element(self, parent_url, developersElement, lastModified):
        print 'Processing '+developersElement.tag+'...'
        for subelement in developersElement.iterchildren():
            print 'Processing tag: '+developersElement.tag+' -> '+subelement.tag
            if subelement.tag == 'developer':
                self.process_riscos_xml_developer_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)                
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_developer_element(self, parent_url, developerElement, lastModified):
        newDocument = {}
        print 'Processing '+developerElement.tag+'...'
        for subelement in developerElement.iterchildren():
            print 'Processing tag: '+developerElement.tag+' -> '+subelement.tag
            if subelement.tag in ['address','contact','email','telephone','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag.lower() == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor               
            elif subelement.tag.lower() == 'name':
                developer = subelement.text
                print 'Developer: '+developer
                newDocument['developer'] = developer
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 

    def process_riscos_xml_errormessages_element(self, parent_url, errormessagesElement, lastModified):
        print 'Processing '+errormessagesElement.tag+'...'
        for subelement in errormessagesElement.iterchildren():
            if subelement.tag.lower() == 'errormessage':
                print 'Processing tag: '+errormessagesElement.tag+' -> '+subelement.tag
                self.process_riscos_xml_errormessage_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef 
    
    def process_riscos_xml_errormessage_element(self, parent_url, errormessageElement, lastModified):
        newDocument = {}
        print 'Processing '+errormessageElement.tag+'...'
        for subelement in errormessageElement.iterchildren():
            print 'Processing tag: '+errormessageElement.tag+' -> '+subelement.tag
            if subelement.tag in ['cause','solution']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag == 'message':
                errormessage = subelement.text
                print 'Error Message: '+errormessage
                newDocument['error_message'] = errormessage
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef
    
    def process_riscos_xml_events_element(self, parent_url, eventsElement, lastModified):
        print 'Processing '+eventsElement.tag+'...'
        for subelement in eventsElement.iterchildren():
            if subelement.tag == 'event':
                print 'Processing tag: '+eventsElement.tag+' -> '+subelement.tag
                self.process_riscos_xml_event_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_event_element(self, parent_url, eventElement, lastModified):
        newDocument = {}
        print 'Processing '+eventElement.tag+'...'
        for subelement in eventElement.iterchildren():
            print 'Processing tag: '+eventElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text      
            elif subelement.tag.lower() == 'date':
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
                print 'Date: '+year+'-'+month+'-'+day
                secsSinceEpoch = int(time.mktime((int(year),int(month),int(day),0,0,0,0,0,0)))
                newDocument['date'] = secsSinceEpoch
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor                
            elif subelement.tag.lower() == 'title':
                print 'Event: '+subelement.text
                newDocument['event'] = subelement.text
            elif subelement.tag.lower() == 'url':
                print 'URL: '+subelement.text
                newDocument['url'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef

    def process_riscos_xml_forums_element(self, parent_url, forumsElement, lastModified):
        print 'Processing '+forumsElement.tag+'...'
        for subelement in forumsElement.iterchildren():
            print 'Processing tag: '+forumsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'forum':
                self.process_riscos_xml_forum_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_forum_element(self, parent_url, forumElement, lastModified):
        newDocument = {}
        print 'Processing '+forumElement.tag+'...'
        #xmlcode = etree.tostring(forumElement)
        #print xmlcode
        for subelement in forumElement.iterchildren():
            print 'Processing tag: '+forumElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'name':
                forum = subelement.text
                print 'Forum: '+forum
                newDocument['forum'] = forum
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
                newDocument['url'] = url
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef   
   
    def process_riscos_xml_computers_element(self, parent_url, computersElement, lastModified):
        print 'Processing '+computersElement.tag+'...'
        for subelement in computersElement.iterchildren():
            print 'Processing tag: '+computersElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'computer':
                self.process_riscos_xml_computer_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)                
            #endif
        #endfor
    #enddef

    def process_riscos_xml_computer_element(self, parent_url, computerElement, lastModified):
        newDocument = {}
        print 'Processing '+computerElement.tag+'...'
        for subelement in computerElement.iterchildren():
            print 'Processing tag: '+computerElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'identifier':
                print 'Identifier: '+subelement.text
                newDocument['identifier'] = subelement.text
            elif subelement.tag.lower() == 'name':
                print 'Computer: '+subelement.text
                newDocument['computer'] = subelement.text
            elif subelement.tag.lower() == 'pricing':
                pricing = self.process_riscos_xml_pricing_element(subelement)
                newDocument['pricing'] = pricing
            elif subelement.tag in ['developer','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef
    
    def process_riscos_xml_peripherals_element(self, parent_url, peripheralsElement, lastModified):
        print 'Processing '+peripheralsElement.tag+'...'
        for subelement in peripheralsElement.iterchildren():
            print 'Processing tag: '+peripheralsElement.tag+' -> '+subelement.tag
            if subelement.tag == 'peripheral':
                self.process_riscos_xml_peripheral_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)                
            #endif
        #endfor
    #enddef 

    def process_riscos_xml_peripheral_element(self, parent_url, peripheralElement, lastModified):
        newDocument = {}       
        print 'Processing '+peripheralElement.tag+'...'
        for subelement in peripheralElement.iterchildren():
            print 'Processing tag: '+peripheralElement.tag+' -> '+subelement.tag  
            if subelement.tag.lower() == 'devicetype':
                print 'Device Type: '+subelement.text
                newDocument['device_type'] = subelement.text          
            elif subelement.tag.lower() == 'name':
                print 'Peripheral: '+subelement.text
                newDocument['peripheral'] = subelement.text
            elif subelement.tag in ['developer','identifier','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor                
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef     
    
    def process_riscos_xml_podules_element(self, parent_url, podulesElement, lastModified):
        print 'Processing '+podulesElement.tag+'...'
        for subelement in podulesElement.iterchildren():
            print 'Processing tag: '+podulesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'podule':
                self.process_riscos_xml_podule_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)                
            #endif
        #endfor
    #enddef

    def process_riscos_xml_podule_element(self, parent_url, poduleElement, lastModified):
        newDocument = {}
        print 'Processing '+poduleElement.tag+'...'
        for subelement in poduleElement.iterchildren():
            print 'Processing tag: '+poduleElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag in ['developer','identifier','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag == 'image':    
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor                
            elif subelement.tag == 'name':
                podule = subelement.text
                print 'Podule: '+podule
                newDocument['podule'] = podule
            elif subelement.tag == 'pricing':
                pricing = self.process_riscos_xml_pricing_element(subelement)
                newDocument['pricing'] = pricing
            elif subelement.tag.lower() == 'relocatablemodules':
                relocatableModules = self.process_riscos_xml_embedded_relocatable_modules_element(subelement)
                newDocument['relocatable_modules'] = relocatableModules
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef    
    
    def process_riscos_xml_faqs_element(self, parent_url, faqsElement, lastModified):
        print 'Processing '+faqsElement.tag+'...'
        for subelement in faqsElement.iterchildren():
            print 'Processing tag: '+faqsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'faq':
                self.process_riscos_xml_faq_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef    
    
    def process_riscos_xml_faq_element(self, parent_url, faqElement, lastModified):
        newDocument = {}       
        print 'Processing '+faqElement.tag+'...'
        for subelement in faqElement.iterchildren():
            print 'Processing tag: '+faqElement.tag+' -> '+subelement.tag
            if subelement.tag == 'image':
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'sourcecode':
                newDocument['source_code'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'programminglanguage':
                        newDocument['programming_languages'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'question':
                print 'Question: '+subelement.text
                newDocument['question'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'answer':
                print 'Answer: '+subelement.text
                newDocument['answer'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef     
    
    def process_riscos_xml_howtos_element(self, parent_url, howtosElement, lastModified):
        print 'Processing '+howtosElement.tag+'...'
        for subelement in howtosElement.iterchildren():
            print 'Processing tag: '+howtosElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'howto':
                self.process_riscos_xml_howto_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef    
    
    def process_riscos_xml_howto_element(self, parent_url, howtoElement, lastModified):
        newDocument = {}       
        print 'Processing '+howtoElement.tag+'...'
        for subelement in howtoElement.iterchildren():
            print 'Processing tag: '+howtoElement.tag+' -> '+subelement.tag
            if subelement.tag == 'image':
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'sourcecode':
                newDocument['source_code'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'programminglanguage':
                        newDocument['programming_languages'] = [value]
                    #endif
                #endfor
            elif subelement.tag == 'task':
                print 'Task: '+subelement.text
                newDocument['howto'] = subelement.text
                for attr, value in subelement.items():
                    if attr == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef      
    
    def process_riscos_xml_projects_element(self, parent_url, projectsElement, lastModified):
        print 'Processing '+projectsElement.tag+'...'
        for subelement in projectsElement.iterchildren():
            print 'Processing tag: '+projectsElement.tag+' -> '+subelement.tag
            if subelement.tag == 'project':
                self.process_riscos_xml_project_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_project_element(self, parent_url, projectElement, lastModified):
        newDocument = {}       
        print 'Processing '+projectElement.tag+'...'
        for subelement in projectElement.iterchildren():
            print 'Processing tag: '+projectElement.tag+' -> '+subelement.tag
            if subelement.tag == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag == 'name':
                name = subelement.text
                print 'Name: '+name
                newDocument['project'] = name
            elif subelement.tag == 'url':
                url = subelement.text
                print 'URL: '+url
                newDocument['url'] = url
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef     
       
    def process_riscos_xml_anniversaries_element(self, parent_url, anniversariesElement, lastModified):
        print 'Processing '+anniversariesElement.tag+'...'
        for subelement in anniversariesElement.iterchildren():
            print 'Processing tag: '+anniversariesElement.tag+' -> '+subelement.tag
            if subelement.tag == 'anniversary':
                self.process_riscos_xml_anniversary_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef
       
    def process_riscos_xml_anniversary_element(self, parent_url, bookElement, lastModified):
        newDocument = {}      
        print 'Processing '+bookElement.tag+'...'
        for subelement in bookElement.iterchildren():
            print 'Processing tag: '+bookElement.tag+' -> '+subelement.tag
            if subelement.tag == 'date':
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
                print 'Date: '+year+'-'+month+'-'+day
                secsSinceEpoch = time.mktime((int(year),int(month),int(day),0,0,0,0,0,0))
                newDocument['date'] = secsSinceEpoch
            elif subelement.tag == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'title':
                print 'Anniversary: '+subelement.text
                newDocument['anniversary'] = subelement.text
            elif subelement.tag == 'url':
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 
       
    def process_riscos_xml_books_element(self, parent_url, booksElement, lastModified):
        print 'Processing '+booksElement.tag+'...'
        for subelement in booksElement.iterchildren():
            print 'Processing tag: '+booksElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'book':
                self.process_riscos_xml_book_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef    
    
    def process_riscos_xml_book_element(self, parent_url, bookElement, lastModified):
        newDocument = {}      
        print 'Processing '+bookElement.tag+'...'
        for subelement in bookElement.iterchildren():
            print 'Processing tag: '+bookElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag == 'isbn':
                print 'ISBN: '+subelement.text
                newDocument['identifier'] = subelement.text
            elif subelement.tag.lower() == 'image':
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'pricing':
                pricing = self.process_riscos_xml_pricing_element(subelement)
                newDocument['pricing'] = pricing
            elif subelement.tag.lower() == 'authors':
                authors = self.process_riscos_xml_authors_element(subelement)
                newDocument['authors'] = authors   
            elif subelement.tag in ['publisher','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag == 'territory':
                print 'Territory: '+subelement.text
                newDocument['territories'] = [subelement.text]
            elif subelement.tag == 'published':
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
                print 'Date: '+year+'-'+month+'-'+day
                secsSinceEpoch = time.mktime((int(year),int(month),int(day),0,0,0,0,0,0))
                newDocument['date'] = secsSinceEpoch
            elif subelement.tag.lower() == 'title':
                print 'Title: '+subelement.text
                newDocument['book'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 

    def process_riscos_xml_magazines_element(self, parent_url, magazinesElement, lastModified):
        print 'Processing '+magazinesElement.tag+'...'
        for subelement in magazinesElement.iterchildren():
            print 'Processing tag: '+magazinesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'magazine':
                self.process_riscos_xml_magazine_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_magazine_element(self, parent_url, magazineElement, lastModified):
        newDocument = {}       
        print 'Processing '+magazineElement.tag+'...'
        for subelement in magazineElement.iterchildren():
            print 'Processing tag: '+magazineElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag.lower() == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'issn':
                print 'ISSN: '+subelement.text
                newDocument['identifier'] = subelement.text
            elif subelement.tag == 'pricing':
                pricing = self.process_riscos_xml_pricing_element(subelement)
                newDocument['pricing'] = pricing
            elif subelement.tag == 'territory':
                print 'Territory: '+subelement.text
                newDocument['territories'] = [subelement.text]
            elif subelement.tag.lower() == 'title':
                print 'Title: '+subelement.text
                newDocument['magazine'] = subelement.text
            elif subelement.tag in ['publisher','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            if newDocument.has_key('territories'):
                newDocument['territories'] = list(set(newDocument['territories']))
            #endif
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 
    
    def process_riscos_xml_services_element(self, parent_url, servicesElement, lastModified):
        print 'Processing '+servicesElement.tag+'...'
        for subelement in servicesElement.iterchildren():
            print 'Processing tag: '+servicesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'service':
                self.process_riscos_xml_service_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_service_element(self, parent_url, serviceElement, lastModified):
        newDocument = {}
        print 'Processing '+serviceElement.tag+'...'
        for subelement in serviceElement.iterchildren():
            print 'Processing tag: '+serviceElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag in ['address','category','email','telephone','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag.lower() == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor               
            elif subelement.tag.lower() == 'name':
                print 'Provider: '+subelement.text
                newDocument['provider'] = subelement.text
            elif subelement.tag.lower() == 'pricing':
                pricing = self.process_riscos_xml_pricing_element(subelement)
                newDocument['pricing'] = pricing
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 
    
    def process_riscos_xml_absolutes_element(self, parent_url, absolutesElement, lastModified):
        print 'Processing '+absolutesElement.tag+'...'
        for subelement in absolutesElement.iterchildren():
            print 'Processing tag: '+absolutesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'absolute':
                self.process_riscos_xml_absolute_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_absolute_element(self, parent_url, absoluteElement, lastModified):
        newDocument = {}
        print 'Processing '+absoluteElement.tag+'...'
        for subelement in absoluteElement.iterchildren():
            print 'Processing tag: '+absoluteElement.tag+' -> '+subelement.tag
            if subelement.tag == 'name':
                absolute = subelement.text
                print 'Absolute: '+absolute
                newDocument['absolutes'] = [absolute]
            elif subelement.tag == 'url':
                url = subelement.text
                print 'URL: '+url
                newDocument['url'] = url
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef
    
    def process_riscos_xml_apps_element(self, parent_url, appsElement, lastModified):
        print 'Processing '+appsElement.tag+'...'
        for subelement in appsElement.iterchildren():
            print 'Processing tag: '+appsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'app':
                self.process_riscos_xml_app_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_app_element(self, parent_url, appElement, lastModified):
        newDocument = {}
        print 'Processing '+appElement.tag+'...'
        for subelement in appElement.iterchildren():
            print 'Processing tag: '+appElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'addressingmode':
                if subelement.text in ['26-bit','32-bit','26/32-bit']:
                    print 'Addressing Mode: '+subelement.text
                    newDocument['addressing_mode'] = subelement.text
                #endif
            elif subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag.lower() == 'arm_architectures':
                arm_architectures = self.process_riscos_xml_arm_architectures_element(subelement)
                newDocument['arm_architectures'] = arm_architectures
            elif subelement.tag == 'authors':
                authors = self.process_riscos_xml_authors_element(subelement)
                newDocument['authors'] = authors   
            elif subelement.tag.lower() in ['copyright','developer','directory','icon_url','identifier','licence','maintainer','purpose','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag.lower() == 'filetypesrun':
                filetypes_run = self.process_riscos_xml_filetypes_run_element(subelement)
                newDocument['filetypes_run'] = filetypes_run
            elif subelement.tag.lower() == 'filetypesset':
                filetypes_set = self.process_riscos_xml_filetypes_set_element(subelement)
                newDocument['filetypes_set'] = filetypes_set
            elif subelement.tag.lower() == 'iconurl':
                print 'Icon URL: '+subelement.text
                newDocument['icon_url'] = subelement.text
            elif subelement.tag == 'image':    
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'keystages':
                keyStages = self.process_riscos_xml_keystages_element(subelement)
                newDocument['key_stages'] = keyStages
            elif subelement.tag == 'released':
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
                print 'Released: '+year+'-'+month+'-'+day
                secsSinceEpoch = time.mktime((int(year),int(month),int(day),0,0,0,0,0,0))
                newDocument['date'] = secsSinceEpoch
            elif subelement.tag.lower() == 'relocatablemodules':
                relocatableModules = self.process_riscos_xml_embedded_relocatable_modules_element(subelement)
                newDocument['relocatable_modules'] = relocatableModules
            elif subelement.tag == 'name':
                print 'Name: '+subelement.text
                newDocument['application_name'] = subelement.text
            elif subelement.tag.lower() == 'moduledependencies':
                newDocument['module_dependencies'] = self.process_riscos_xml_module_dependencies_element(subelement)
            elif subelement.tag == 'pricing':
                newDocument['pricing'] = self.process_riscos_xml_pricing_element(subelement)
            elif subelement.tag.lower() == 'programminglanguages':
                newDocument['programming_languages'] = self.process_riscos_xml_programming_languages_element(subelement)
            elif subelement.tag.lower() == 'systemvariables':
                newDocument['system_variables'] = self.process_riscos_xml_system_variables_element(subelement)
            elif subelement.tag == 'territories':
                newDocument['territories'] = self.process_riscos_xml_territories_element(subelement)
            elif subelement.tag == 'utilities':
                newDocument['utilities'] = self.process_riscos_xml_embedded_utilities_element(subelement)
            elif subelement.tag == 'version':
                print 'Version: '+subelement.text
                newDocument['application_version'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef

    def process_riscos_xml_arm_architectures_element(self, armArchitecturesElement):
        armArchitectures = []
        for subelement in armArchitecturesElement.iterchildren():
            print 'Processing tag: '+armArchitecturesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() in ['armv2','armv3','armv4','armv5','armv6','armv7']:
                armArchitecture = subelement.tag
                armArchitecture = armArchitecture.replace('arm','ARM')
                armArchitectures.append(subelement.tag)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return armArchitectures
    #enddef
    
    def process_riscos_xml_authors_element(self, authorsElement):
        authors = []
        for subelement in authorsElement.iterchildren():
            if subelement.tag.lower() == 'author':
                authors.append(subelement.text)
            #endif
        #endfor
        return authors
    #enddef
    
    def process_riscos_xml_module_dependencies_element(self, moduleDependenciesElement):
        moduleDependencies = []
        for subelement in moduleDependenciesElement.iterchildren():
            print 'Processing tag: '+moduleDependenciesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'moduledependency':
                moduleDependency = self.process_riscos_xml_module_dependency_element(subelement)
                moduleDependencies.append(moduleDependency)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return moduleDependencies
    #enddef
    
    def process_riscos_xml_module_dependency_element(self, moduleDependencyElement):
        moduleDependency = {}
        print 'Processing '+moduleDependencyElement.tag+'...'
        for subelement in moduleDependencyElement.iterchildren():
            print 'Processing tag: '+moduleDependencyElement.tag+' -> '+subelement.tag
            if subelement.tag == 'name':
                print 'Name: '+subelement.text
                moduleDependency['name'] = subelement.text
            elif subelement.tag == 'version':
                print 'Version: '+subelement.text
                moduleDependency['version'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return moduleDependency   
    #enddef
    
    def process_riscos_xml_embedded_relocatable_modules_element(self, relocatableModulesElement):
        relocatableModules = []
        for subelement in relocatableModulesElement.iterchildren():
            print 'Processing tag: '+relocatableModulesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'relocatablemodule':
                relocatableModule = self.process_riscos_xml_embedded_relocatable_module_element(subelement)
                relocatableModules.append(relocatableModule)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return relocatableModules
    #enddef
    
    def process_riscos_xml_embedded_relocatable_module_element(self, relocatableModuleElement):
        relocatableModule = {}
        print 'Processing '+relocatableModuleElement.tag+'...'
        for subelement in relocatableModuleElement.iterchildren():
            print 'Processing tag: '+relocatableModuleElement.tag+' -> '+subelement.tag
            if subelement.tag == 'name':
                print 'Name: '+subelement.text
                relocatableModule['name'] = subelement.text
            elif subelement.tag.lower() == 'softwareinterrupts':
                relocatableModule['software_interrupts'] = self.process_riscos_xml_software_interrupts_element(subelement)
            elif subelement.tag.lower() == 'starcommands':
                relocatableModule['star_commands'] = self.process_riscos_xml_star_commands_element(subelement)
            elif subelement.tag == 'version':
                print 'Version: '+subelement.text
                relocatableModule['version'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return relocatableModule   
    #enddef
    
    def process_riscos_xml_pricing_element(self, pricingElement):
        pricing = []
        for subelement in pricingElement.iterchildren():
            print 'Processing tag: '+pricingElement.tag+' -> '+subelement.tag
            currency = ""
            duration = ""
            upgradeFrom = ""
            upgradeTo = ""
            for attr, value in subelement.items():
                if attr == 'currency':
                    currency = value
                elif attr == 'duration':
                    duration = value
                elif attr == 'from':
                    upgradeFrom = value
                elif attr == 'to':
                    upgradeTo = value
                #endif
            #endfor
            if subelement.tag.lower() == 'ebook':
                pricing.append({'type':'ebook','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'hardback':
                pricing.append({'type':'hardback','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'hourly':
                pricing.append({'type':'hourly','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'individual':
                pricing.append({'type':'individual','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'issue':
                pricing.append({'type':'issue','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'single':
                pricing.append({'type':'single','currency':currency,'price':subelement.text})               
            elif subelement.tag.lower() == 'singleuser':
                pricing.append({'type':'singleuser','currency':currency,'price':subelement.text})            
            elif subelement.tag.lower() == 'sitelicence':
                pricing.append({'type':'sitelicence','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'softback':
                pricing.append({'type':'softback','currency':currency,'price':subelement.text})
            elif subelement.tag.lower() == 'subscription':
                if duration:
                    pricing.append({'type':'subscription','currency':currency,'duration':duration,'price':subelement.text})
                else:
                    pricing.append({'type':'subscription','currency':currency,'price':subelement.text})
                #endif
            elif subelement.tag.lower() == 'upgrade':
                pricing.append({'type':'upgrade','from':upgradeFrom,'to':upgradeTo,'currency':currency,'price':subelement.text})
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return pricing
    #enddef
    
    def process_riscos_xml_programming_languages_element(self, programmingLanguagesElement):
        programming_languages = []
        for subelement in programmingLanguagesElement.iterchildren():
            print 'Processing tag: '+programmingLanguagesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'programming_language':
                programming_languages.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return programming_languages
    #enddef
    
    def process_riscos_xml_system_variables_element(self, systemVariablesElement):
        system_variables = []
        for subelement in systemVariablesElement.iterchildren():
            print 'Processing tag: '+systemVariablesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'systemvariable':
                system_variables.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return system_variables
    #enddef
    
    def process_riscos_xml_territories_element(self, territoriesElement):
        territories = []
        for subelement in territoriesElement.iterchildren():
            print 'Processing tag: '+territoriesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'territory':
                territories.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return territories
    #enddef
    
    def process_riscos_xml_filetypes_run_element(self, parent_url, filetypesRunElement, lastModified):
        filetypes_run = []
        print 'Processing '+filetypesRunElement.tag+'...'
        for subelement in filetypesRunElement.iterchildren():
            print 'Processing tag: '+filetypesRunElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'filetyperun':
                filetypes_run.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return filetypes_run
    #enddef
    
    def process_riscos_xml_filetypes_set_element(self, parent_url, filetypesSetElement, lastModified):
        filetypes_set = []
        print 'Processing '+filetypesSetElement.tag+'...'
        for subelement in filetypesSetElement.iterchildren():
            print 'Processing tag: '+filetypesSetElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'filetypeset':
                filetypes_set.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return filetypes_set
    #enddef  
    
    def process_riscos_xml_fonts_element(self, parent_url, fontsElement, lastModified):
        print 'Processing '+fontsElement.tag+'...'
        for subelement in fontsElement.iterchildren():
            print 'Processing tag: '+fontsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'font':
                self.process_riscos_xml_font_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_font_element(self, parent_url, fontElement, lastModified):
        newDocument = {}
        print 'Processing '+fontElement.tag+'...'
        for subelement in fontElement.iterchildren():
            print 'Processing tag: '+fontElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'image':
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'name':
                print 'Font: '+subelement.text
                newDocument['font'] = [subelement.text]
            elif subelement.tag.lower() == 'url':
                print 'URL: '+subelement.text
                newDocument['url'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef

    def process_riscos_xml_keystages_element(self, keyStagesElement):
        keyStages = []
        print 'Processing '+keyStagesElement.tag+'...'
        for subelement in keyStagesElement.iterchildren():
            print 'Processing tag: '+keyStagesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'keystage':
                keyStages.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return keyStages
    #enddef

    def process_riscos_xml_parameters_element(self, parametersElement):
        parameters = []
        for subelement in parametersElement.iterchildren():
            print 'Processing tag: '+parametersElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'parameter':
                parameter = {}
                for attr, value in subelement.items():
                    if attr == 'name':
                        parameter['name'] = value
                    elif attr == 'description':
                        parameter['description'] = value
                    #endif
                #endfor
                parameters.append(parameter)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return parameters
    #enddef
    
    def process_riscos_xml_on_entry_element(self, onEntryElement):
        onEntry = []
        for subelement in onEntryElement.iterchildren():
            print 'Processing tag: '+onEntryElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'register':
                register = {}
                for attr, value in subelement.items():
                    if attr == 'number':
                        register['number'] = value
                    elif attr == 'description':
                        register['description'] = value
                    #endif
                #endfor
                onEntry.append(register)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return onEntry
    #enddef
    
    def process_riscos_xml_on_exit_element(self, onExitElement):
        onExit = []
        for subelement in onExitElement.iterchildren():
            print 'Processing tag: '+onExitElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'register':
                register = {}
                for attr, value in subelement.items():
                    if attr == 'number':
                        register['number'] = value
                    elif attr == 'description':
                        register['description'] = value
                    #endif
                #endfor
                onExit.append(register)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return onExit
    #enddef
    
    def process_riscos_xml_related_vectors_element(self, relatedVectorsElement):
        relatedVectors = []
        print 'Processing '+relatedVectorsElement.tag+'...'
        for subelement in relatedVectorsElement.iterchildren():
            print 'Processing tag: '+relatedVectorsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'relatedvector':
                relatedVectors.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return relatedVectors
    #enddef
    
    def process_riscos_xml_related_swis_element(self, relatedSwisElement):
        relatedSwis = []
        print 'Processing '+relatedSwisElement.tag+'...'
        for subelement in relatedSwisElement.iterchildren():
            print 'Processing tag: '+relatedSwisElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'relatedswi':
                relatedSwis.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return relatedSwis
    #enddef
    
    def process_riscos_xml_related_commands_element(self, relatedCommandsElement):
        relatedCommands = []
        print 'Processing '+relatedCommandsElement.tag+'...'
        for subelement in relatedCommandsElement.iterchildren():
            print 'Processing tag: '+relatedCommandsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'relatedcommand':
                relatedCommands.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return relatedCommands
    #enddef
    
    def process_riscos_xml_interrupts_element(self, interruptsElement):
        interrupts = []
        print 'Processing '+interruptsElement.tag+'...'
        for subelement in interruptsElement.iterchildren():
            print 'Processing tag: '+interruptsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'interrupt':
                interrupts.append(subelement.text)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return interrupts
    #enddef
    
    def process_riscos_xml_standalone_relocatable_modules_element(self, parent_url, modulesElement, lastModified):
        print 'Processing '+modulesElement.tag+'...'
        for subelement in modulesElement.iterchildren():
            print 'Processing tag: '+modulesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'relocatablemodule':
                self.process_riscos_xml_standalone_relocatable_module_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_standalone_relocatable_module_element(self, parent_url, moduleElement, lastModified):
        newDocument = {}
        addressingMode = ""
        module = ""
        softwareinterrupts = ""
        star_commands = ""
        version = ""
        print 'Processing '+moduleElement.tag+'...'
        for subelement in moduleElement.iterchildren():
            print 'Processing tag: '+moduleElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'addressingmode':
                addressingMode = subelement.text
                print 'Addressing mode: '+addressingMode
            elif subelement.tag.lower() == 'name':
                module = subelement.text
                print 'Module: '+module
            elif subelement.tag.lower() == 'softwareinterrupts':
                softwareinterrupts = self.process_riscos_xml_software_interrupts_element(subelement)
            elif subelement.tag.lower() == 'starcommands':
                star_commands = self.process_riscos_xml_star_commands_element(subelement)
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
                newDocument['url'] = url
            elif subelement.tag.lower() == 'version':
                version = subelement.text
                print 'Version: '+version
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if module:
            subDocument = {}
            subDocument['name'] = module
            if softwareinterrupts:
                subDocument['software_interrupts'] = softwareinterrupts
            #endif
            if star_commands:
                subDocument['star_commands'] = star_commands
            #endif
            if version:
                subDocument['version'] = version
            #endif
            if addressingMode:
                subDocument['addressing_mode'] = addressingMode
            #endif
            newDocument['relocatable_modules'] = [subDocument]
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef
    
    def process_riscos_xml_software_interrupts_element(self, softwareinterruptsElement):
        softwareinterrupts = []
        print 'Processing '+softwareinterruptsElement.tag+'...'
        for subelement in softwareinterruptsElement.iterchildren():
            print 'Processing tag: '+softwareinterruptsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'softwareinterrupt':
                softwareinterrupt = self.process_riscos_xml_software_interrupt_element(subelement)
                softwareinterrupts.append(softwareinterrupt)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return softwareinterrupts      
    #enddef
    
    def process_riscos_xml_software_interrupt_element(self, softwareinterruptElement):
        softwareinterrupt = {}
        print 'Processing '+softwareinterruptElement.tag+'...'
        for subelement in softwareinterruptElement.iterchildren():
            print 'Processing tag: '+softwareinterruptElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'hexnumber':
                print 'Hex Number: '+subelement.text
                softwareinterrupt['hex_number'] = subelement.text
            elif subelement.tag == 'interrupts':
                interrupts = self.process_riscos_xml_interrupts_element(subelement)
                softwareinterrupt['interrupts'] = interrupts
            elif subelement.tag == 'name':
                print 'Software Interrupt: '+subelement.text
                softwareinterrupt['name'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'reasoncode':
                        softwareinterrupt['reason_code'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'onentry':
                onEntry = self.process_riscos_xml_on_entry_element(subelement)
                softwareinterrupt['on_entry'] = onEntry
            elif subelement.tag.lower() == 'onexit':
                onExit = self.process_riscos_xml_on_exit_element(subelement)
                softwareinterrupt['on_exit'] = onExit
            elif subelement.tag.lower() == 'processormode':
                print 'Processor Mode: '+subelement.text
                softwareinterrupt['processor_mode'] = subelement.text
            elif subelement.tag.lower() == 'reasoncode':
                print 'Reason Code: '+subelement.text
                softwareinterrupt['reason_code'] = subelement.text
            elif subelement.tag.lower() == 'reentrancy':
                print 'Re-entrancy: '+subelement.text
                softwareinterrupt['re_entrancy'] = subelement.text
            elif subelement.tag.lower() == 'relatedswis':
                relatedSwis = self.process_riscos_xml_related_swis_element(subelement)
                softwareinterrupt['related_swis'] = relatedSwis
            elif subelement.tag.lower() == 'relatedvectors':
                relatedVectors = self.process_riscos_xml_related_vectors_element(subelement)
                softwareinterrupt['related_vectors'] = relatedVectors
            elif subelement.tag.lower() == 'summary':
                print 'Summary: '+subelement.text
                softwareinterrupt['summary'] = subelement.text
            elif subelement.tag == 'use':
                print 'Use: '+subelement.text
                softwareinterrupt['use'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return softwareinterrupt    
    #enddef
    
    def process_riscos_xml_star_commands_element(self, starcommandsElement):
        starcommands = []
        print 'Processing '+starcommandsElement.tag+'...'
        for subelement in starcommandsElement.iterchildren():
            print 'Processing tag: '+starcommandsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'starcommand':
                starcommand = self.process_riscos_xml_star_command_element(subelement)
                starcommands.append(starcommand)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return starcommands     
    #enddef
    
    def process_riscos_xml_star_command_element(self, starcommandElement):
        newDocument = {}
        print 'Processing '+starcommandElement.tag+'...'
        for subelement in starcommandElement.iterchildren():
            print 'Processing tag: '+starcommandElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'example':
                print 'Example: '+subelement.text
                newDocument['example'] = subelement.text
            elif subelement.tag.lower() == 'name':
                print 'Star Command: '+subelement.text
                newDocument['name'] = subelement.text
            elif subelement.tag == 'parameters':
                parameters = self.process_riscos_xml_parameters_element(subelement)
                newDocument['parameters'] = parameters
            elif subelement.tag.lower() == 'relatedcommands':
                relatedCommands = self.process_riscos_xml_related_commands_element(subelement)
                newDocument['related_commands'] = relatedCommands
            elif subelement.tag == 'summary':
                print 'Summary: '+subelement.text
                newDocument['summary'] = subelement.text
            elif subelement.tag == 'syntax':
                print 'Syntax: '+subelement.text
                newDocument['syntax'] = subelement.text
            elif subelement.tag == 'use':
                print 'Use: '+subelement.text
                newDocument['use'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return newDocument
    #enddef
    
    def process_riscos_xml_monitor_definition_files_element(self, parent_url, monitorDefinitionFilesElement, lastModified):
        print 'Processing '+monitorDefinitionFilesElement.tag+'...'
        for subelement in monitorDefinitionFilesElement.iterchildren():
            print 'Processing tag: '+monitorDefinitionFilesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() in ['monitordefinitionfile','monitor_definition_file','mdf']:
                self.process_riscos_xml_monitor_definition_file_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef
    
    def process_riscos_xml_monitor_definition_file_element(self, parent_url, monitorDefinitionFileElement, lastModified):
        newDocument = {}
        print 'Processing '+monitorDefinitionFileElement.tag+'...'
        for subelement in monitorDefinitionFileElement.iterchildren():
            print 'Processing tag: '+monitorDefinitionFileElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'monitor':
                monitor = subelement.text
                print 'Monitor: '+monitor
                newDocument['monitor_definition_files'] = [monitor]
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
                newDocument['url'] = url
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if monitor and url:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef
    
    def process_riscos_xml_printer_definition_files_element(self, parent_url, printerDefinitionFilesElement, lastModified):
        print 'Processing '+printerDefinitionFilesElement.tag+'...'
        for subelement in printerDefinitionFilesElement.iterchildren():
            print 'Processing tag: '+printerDefinitionFilesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() in ['printer_definition_file','printerdefinitionfile','pdf']:
                self.process_riscos_xml_printer_definition_file_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor         
    #enddef
    
    def process_riscos_xml_printer_definition_file_element(self, parent_url, printerDefinitionFileElement, lastModified):
        newDocument = {}
        print 'Processing '+printerDefinitionFileElement.tag+'...'
        for subelement in printerDefinitionFileElement.iterchildren():
            print 'Processing tag: '+printerDefinitionFileElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'printer':
                printer = subelement.text
                print 'Printer: '+printer
                newDocument['printer_definition_files'] = [printer]
            elif subelement.tag.lower() == 'url':
                url = subelement.text
                print 'URL: '+url
                newDocument['url'] = url
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef

    def process_riscos_xml_standalone_utilities_element(self, parent_url, utilitiesElement, lastModified):
        print 'Processing '+utilitiesElement.tag+'...'
        for subelement in utilitiesElement.iterchildren():
            print 'Processing tag: '+utilitiesElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'utility':
                self.process_riscos_xml_standalone_utility_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_standalone_utility_element(self, parent_url, utilityElement, lastModified):
        newDocument = {}
        utility = {}
        print 'Processing '+utilityElement.tag+'...'
        for subelement in utilityElement.iterchildren():
            print 'Processing tag: '+utilityElement.tag+' -> '+subelement.tag
            if subelement.tag == 'name':
                print 'Utility: '+subelement.text
                utility['name'] = subelement.text
            elif subelement.tag == 'syntax':
                print 'Syntax: '+subelement.text
                utility['syntax'] = subelement.text
            elif subelement.tag == 'url':
                print 'URL: '+subelement.text
                newDocument['url'] = subelement.text
            elif subelement.tag == 'version':
                print 'Version: '+subelement.text
                utility['version'] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if utility:
            newDocument['utilities'] = [utility]
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef    
    
    def process_riscos_xml_embedded_utilities_element(self, parent_url, utilitiesElement, lastModified):
        utilities = []
        print 'Processing '+utilitiesElement.tag+'...'
        for utilityElement in utilitiesElement.iterchildren():
            print 'Processing tag: '+utilitiesElement.tag+' -> '+utilityElement.tag
            if utilityElement.tag == 'utility':
                utility = {}
                print 'Processing '+utilityElement.tag+'...'
                for subelement in utilityElement.iterchildren():
                    print 'Processing tag: '+utilityElement.tag+' -> '+subelement.tag
                    if subelement.tag == 'name':
                        print 'Utility: '+subelement.text
                        utility['name'] = subelement.text
                    elif subelement.tag == 'syntax':
                        print 'Syntax: '+subelement.text
                        utility['syntax'] = subelement.text
                    elif subelement.tag == 'version':
                        print 'Version: '+subelement.text
                        utility['version'] = subelement.text
                    else:
                        print "Unknown riscos.xml code: "+etree.tostring(subelement)
                    #endif
                #endfor
                if utility.has_key('name') and utility['name']:
                    utilities.append(utility)
                #endif
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        return utilities
    #enddef

    def process_riscos_xml_glossary_element(self, parent_url, glossaryElement, lastModified):
        print 'Processing '+glossaryElement.tag+'...'
        for subelement in glossaryElement.iterchildren():
            print 'Processing tag: '+glossaryElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'entry':
                self.process_riscos_xml_entry_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef

    def process_riscos_xml_entry_element(self, parent_url, entryElement, lastModified):
        newDocument = {}
        term = ""
        definition = ""
        print 'Processing '+entryElement.tag+'...'
        for subelement in entryElement.iterchildren():
            print 'Processing tag: '+entryElement.tag+' -> '+subelement.tag
            if subelement.tag == 'image':
                for attr, value in subelement.items():
                    if attr == 'caption':
                        newDocument['image_caption'] = value
                    elif attr == 'url':
                        newDocument['image_url'] = value
                    #endif
                #endfor
            elif subelement.tag.lower() == 'sourcecode':
                newDocument['source_code'] = subelement.text
                for attr, value in subelement.items():
                    if attr.lower() == 'programminglanguage':
                        newDocument['programming_languages'] = [value]
                    #endif
                #endfor
            if subelement.tag.lower() == 'term':
                term = subelement.text
                print 'Term: '+term
                newDocument['glossary_term'] = term
            elif subelement.tag.lower() == 'definition':
                definition = subelement.text
                print 'Definition: '+definition
                newDocument['glossary_definition'] = definition
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)                
            #endif
        #endfor
        if term and definition:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef

    def process_riscos_xml_usergroups_element(self, parent_url, usergroupsElement, lastModified):
        print 'Processing '+usergroupsElement.tag+'...'
        for subelement in usergroupsElement.iterchildren():
            print 'Processing tag: '+usergroupsElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'usergroup':
                self.process_riscos_xml_usergroup_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_usergroup_element(self, parent_url, usergroupElement, lastModified):
        newDocument = {}
        print 'Processing '+usergroupElement.tag+'...'
        for subelement in usergroupElement.iterchildren():
            print 'Processing tag: '+usergroupElement.tag+' -> '+subelement.tag
            if subelement.tag.lower() == 'adverturl':
                print 'Advert URL: '+subelement.text
                newDocument['advert_url'] = subelement.text
            elif subelement.tag in ['address','contact','email','telephone','url']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            elif subelement.tag == 'description':
                description = subelement.text
                print 'Description: '+description
                newDocument['description'] = description
                for attr, value in subelement.items():
                    if attr.lower() == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor
            elif subelement.tag == 'name':
                usergroup = subelement.text
                print 'User group: '+usergroup
                newDocument['user_group'] = usergroup
            elif subelement.tag == 'pricing':
                pricing = self.process_riscos_xml_pricing_element(subelement)
                newDocument['pricing'] = pricing
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef 

    def process_riscos_xml_videos_element(self, parent_url, videosElement, lastModified):
        print 'Processing '+videosElement.tag+'...'
        for subelement in videosElement.iterchildren():
            print 'Processing tag: '+videosElement.tag+' -> '+subelement.tag
            if subelement.tag == 'video':
                self.process_riscos_xml_video_element(parent_url, subelement, lastModified)
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
    #enddef   
    
    def process_riscos_xml_video_element(self, parent_url, videoElement, lastModified):
        newDocument = {}
        print 'Processing '+videoElement.tag+'...'
        for subelement in videoElement.iterchildren():
            print 'Processing tag: '+videoElement.tag+' -> '+subelement.tag
            if subelement.tag == 'description':
                print 'Description: '+subelement.text
                newDocument['description'] = subelement.text
                for attr, value in subelement.items():
                    if attr == 'territory':
                        newDocument['territories'] = [value]
                    #endif
                #endfor                
            elif subelement.tag == 'title':
                print 'Video: '+subelement.text
                newDocument['video'] = subelement.text
            elif subelement.tag in ['height','url','width']:
                print subelement.tag.capitalize()+': '+subelement.text
                newDocument[subelement.tag] = subelement.text
            else:
                print "Unknown riscos.xml code: "+etree.tostring(subelement)
            #endif
        #endfor
        if newDocument:
            self.insert_riscos_xml_record_with_housekeeping(newDocument, parent_url, lastModified)
        #endif
    #enddef
    
    def insert_riscos_xml_record_with_housekeeping(self, newDocument, parent_url, lastModified):
        epoch = int(time.time())
        newDocument['riscos_xml'] = parent_url
        newDocument['parent_url'] = parent_url
        if not newDocument.has_key('date') or not newDocument['date']:
            if lastModified:
                newDocument['date'] = lastModified
            #endif
        #endif
        newDocument['last_scanned'] = epoch
        newDocument['next_scan'] = epoch + self.periodMonth
        self.riscosCollection.insert(newDocument)
    #enddef
    
    def analyse_atom_feed(self, url, data):
        for atomFeedDocument in self.riscosCollection.find({'parent_url':url}):
            print 'Removing atom feed entry for '+atomFeedDocument['parent_url']+'...'
            self.riscosCollection.remove({'_id':ObjectId(atomFeedDocument['_id'])})
        #endfor
        if re.search('<feed(.*?)</feed>',data):
            epoch = int(time.time())
            iconUrl = ""
            print "feed tag found..."
            xmlCode = etree.XML(data)
            for subElement in xmlCode.iterchildren():
                if subElement.tag == 'entry':
                    link = ""
                    summary = ""
                    title = ""
                    updated = ""
                    for entryElement in subElement.iterchildren():
                        if entryElement.tag == 'link':
                            for attr, value in entryElement.items():
                                if attr.lower() == 'href':
                                    link = value
                                #endif
                            #endfor       
                        elif entryElement.tag == 'summary':
                            summary = entryElement.text
                            #summary = summary.replace('&lt;','<')
                            #summary = summary.replace('&gt;','>')
                            summary = summary.replace('<p>','<p align="left">')
                        elif entryElement.tag == 'title':
                            title = entryElement.text
                        elif entryElement.tag == 'updated':
                            updated = entryElement.text
                        #endif
                    #endfor
                    if self.content_riscos_related(title) or self.content_riscos_related(summary):
                        print 'Adding new ATOM entry...'
                        newDocument = {}
                        newDocument['syndicated_feed_item_title'] = title
                        newDocument['syndicated_feed_item_description'] = summary
                        if iconUrl:
                            newDocument['icon_url'] = iconUrl
                        #endif
                        if link:
                            if not self.url_in_a_collection(link) and not self.suspended_url(link) and not self.blacklisted_url(link):
                                self.insert_url_into_urls(link, "", 0, epoch, False, False, False)
                            #endif
                            newDocument['url'] = link
                        #endif
                        newDocument['parent_url'] = url
                        newDocument['syndicated_feed'] = url
                        newDocument['last_scanned'] = epoch
                        if updated:
                            newDocument['date'] = updated
                        else:
                            newDocument['date'] = epoch
                        #endif
                        newDocument['next_scan'] = epoch + self.periodWeek
                        print "Inserting into riscos: "+title
                        if newDocument.has_key('strike'):
                            del newDocument['strike']
                        #endif
                        self.riscosCollection.insert(newDocument)
                    #endif
                elif subElement.tag == 'logo':
                    iconUrl = subElement.text
                #endif
            #endfor
        #endif
    #enddef
    
    def analyse_rss_feed(self, url, data):
        for rssFeedDocument in self.riscosCollection.find({'parent_url':url}):
            print 'Removing rss feed entry for '+rssFeedDocument['parent_url']+'...'
            self.riscosCollection.remove({'_id':ObjectId(rssFeedDocument['_id'])})
        #endfor  
        epoch = int(time.time())
        data = data.replace('\n','')
        data = data.replace('\r','')
        if re.search('<rss(.*?)</rss>',data):
            channelPattern = re.compile('<channel>(.*?)</channel>')
            itemPattern = re.compile('<item>(.*?)</item>')
            titlePattern = re.compile('<title>(.*?)</title>')
            linkPattern = re.compile('<link>(.*?)</link>')
            pubDatePattern = re.compile('<pubDate>.*?\s(\d\d)\s([A-Z][a-z][a-z])\s(\d{4})\s.*?</pubDate>')
            descriptionPattern = re.compile('<description>(.*?)</description>')
            channels = channelPattern.findall(data)
            for channel in channels:
                itemResults = itemPattern.findall(channel)
                if itemResults:
                    for itemResult in itemResults:
                        title = ""
                        description = ""
                        link = ""
                        publicationDate = ""
                        titleResults = titlePattern.findall(itemResult)
                        if titleResults:
                            title = titleResults[0]
                        #endif
                        linkResults = linkPattern.findall(itemResult)
                        if linkResults:
                            link = linkResults[0]
                        #endif                        
                        descriptionResults = descriptionPattern.findall(itemResult)
                        if descriptionResults:
                            description = descriptionResults[0]
                            description = description.replace('&lt;','<')
                            description = description.replace('&gt;','>')
                            description = description.replace('<p>','<p align="left">')
                        #endif

                        pubDateResults = pubDatePattern.findall(itemResult)
                        if pubDateResults:
                            day = int(pubDateResults[0][0])                          
                            month = self.months.index(pubDateResults[0][1])+1
                            year = int(pubDateResults[0][2])
                            publicationDate = time.mktime((int(year),int(month),int(day),0,0,0,0,0,0))
                        #endif
                        
                        if title and (self.content_riscos_related(title) or self.content_riscos_related(description)):
                            newDocument = {}
                            newDocument['parent_url'] = url
                            newDocument['syndicated_feed'] = url
                            if publicationDate:
                                newDocument['date'] = publicationDate
                            else:
                                newDocument['date'] = epoch
                            #endif
                            newDocument['syndicated_feed_item_title'] = title
                            if description:
                                newDocument['syndicated_feed_item_description'] = description
                            #endif
                            if link:
                                newDocument['url'] = link
                            #endif
                            newDocument['last_scanned'] = epoch
                            newDocument['next_scan'] = epoch + self.periodWeek
                            self.riscosCollection.insert(newDocument)
                            if not self.url_in_a_collection(linkResults[0]) and not self.suspended_url(linkResults[0]) and not self.blacklisted_url(linkResults[0]):
                                self.insert_url_into_urls(linkResults[0], "", 0, epoch, False, False, False)                 
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
                if not self.content_riscos_related(document['page_title']):
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
    
    def content_riscos_related(self, data):
        contentRiscosRelated = False
        for searchTerm in ['RISC OS','RISC&nbsp;OS','RISC-OS','RISCOS','RiscOS','risc os','risc-os','riscos','Archimedes','RiscPC','Qercus','Iyonix','Risc PC','Acorn Computer','riscpkg']:
            if data.__contains__(searchTerm):
                contentRiscosRelated = True
                break
            #endif
        #endfor
        return contentRiscosRelated
    #enddef
    
    def update_apps(self, url, document, apps):
        epoch = int(time.time())
        for [absolutes,appDate,appDir,appName,appVer,armArchitectures,author,categories,copyright,description,dtpFormats,filetypesRun,filetypesSet,fonts,help,licence,maintainer,monitorDefinitionFiles,packageName,packageSection,packageVersion,printerDefinitionFiles,priority,programmingLanguages,relocatableModules,relocatableModulesDependantUpon,riscOsVers,source,territories,systemVariables,toolboxRequired,utilities] in apps:
            existingDocument = ""
            if appDir:
                existingDocument = self.riscosCollection.find_one({'url':url,'directory':appDir})
            #endif
            if existingDocument:
                existingDocument['zip_file'] = url
                existingDocument['last_scanned'] = epoch
                existingDocument['next_scan'] = epoch + self.periodYear
                if absolutes:
                    existingDocument['absolutes'] = absolutes
                #endif
                if appDate:
                    existingDocument['date'] = appDate
                #endif
                if appName and appName != 'ProgInfo':
                    existingDocument['application_name'] = appName
                #endif
                if appVer:
                    existingDocument['application_version'] = appVer
                #endif
                if armArchitectures:
                    existingDocument['arm_architectures'] = armArchitectures
                #endif
                if author:
                    existingDocument['authors'] = [author]
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
                if filetypesRun:
                    existingDocument['filetypes_run'] = filetypesRun
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
                if licence:
                    existingDocument['licence'] = licence
                #endif
                if maintainer:
                    existingDocument['maintainer'] = maintainer
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
                    existingDocument['module_dependencies'] = relocatableModulesDependantUpon
                #endif
                if riscOsVers:
                    existingDocument['riscos_versions'] = riscOsVers
                #endif
                if source:
                    existingDocument['source'] = source
                #endif          
                if territories:
                    existingDocument['territories'] = list(set(territories))
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
                    subDocument['date'] = appDate
                #endif
                if appDir:
                    subDocument['directory'] = appDir
                #endif
                if appName and appName != 'ProgInfo':
                    subDocument['application_name'] = appName
                #endif
                if appVer:
                    subDocument['application_version'] = appVer
                #endif
                if armArchitectures:
                    existingDocument['arm_architectures'] = armArchitectures
                #endif
                if author:
                    subDocument['authors'] = [author]
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
                if filetypesRun:
                    subDocument['filetypes_run'] = filetypesRun
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
                if licence:
                    subDocument['licence'] = licence
                #endif
                if maintainer:
                    subDocument['maintainer'] = maintainer
                #endif
                if riscOsVers:
                    subDocument['riscos_versions'] = riscOsVers
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
                    subDocument['module_dependencies'] = relocatableModulesDependantUpon
                #endif
                if source:
                    subDocument['source'] = source
                #endif          
                if territories:
                    subDocument['territories'] = list(set(territories))
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
    
    def analyse_zip_file(self, url, data):
        apps = []
        latestMessage = ""
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
                        armArchitectures = []
                        author = ""
                        categories = []
                        copyright = ""
                        description = ""
                        dtpFormats = []
                        filetypesSet = []
                        filetypesRun = []
                        fonts = []
                        help = ""
                        licence = ""
                        maintainer = ""
                        riscOsVers = []
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
                                            year = int(appDate[7:])
                                            if appDate[3:6] in self.months:
                                                month = self.months.index(appDate[3:6])+1
                                            #endif
                                            day = int(appDate[:2])
                                            appDate = int(time.mktime((year,month,day,0,0,0,0,0,0)))
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
                                        licence = results[0]
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
                                            year = int(appDate[7:])
                                            if appDate[3:6] in self.months:
                                                month = self.months.index(appDate[3:6])+1
                                            #endif
                                            day = int(appDate[:2])
                                            appDate = int(time.mktime((year,month,day,0,0,0,0,0,0)))
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
                                        riscOsVers.append(3.70)
                                    elif '3.60' in results:
                                        riscOsVers.append(3.60)
                                    elif '3.50' in results:
                                        riscOsVers.append(3.50)
                                    elif '3.11' in results:
                                        riscOsVers.append(3.11)
                                    elif '3.10' in results:
                                        riscOsVers.append(3.10)
                                    elif '3.00' in results or '3.0' in results:
                                        riscOsVers.append(3.00)
                                    elif '2.00' in results:
                                        riscOsVers.append(2.00)
                                    #endif
                                    
                                    if '6.20' in results:
                                        riscOsVers.append(6.20)
                                    elif '6.00' in results:
                                        riscOsVers.append(6.00)
                                    elif '4.00' in results:
                                        riscOsVers.append(4.00)
                                    #endif
                    
                                    if '5.00' in results:
                                        riscOsVers.append(5.00)
                                    #endif
                                #endif

                                results = self.runTypePattern.findall(contents)
                                if results != []:
                                    for result in results:
                                        if not result in filetypesRun:
                                            filetypesRun.append(result)
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
                        
                        if riscOsVers and not armArchitectures:
                            for riscOsVer in riscOsVers:
                                if riscOsVer in ['3.70','3.71']:
                                    armArchitectures.append('ARMv4')
                                elif riscOsVer in ['3.50','3.60']:
                                    armArchitectures.append('ARMv3')
                                elif riscOsVer in ['2.00','3.0','3.00','3.10','3.11']: 
                                    armArchitectures.append('ARMv2')
                                #endif                            
                            #endfor
                        #endif
                        
                        for component in [absolutes,appDate,appDir,appName,appVer,armArchitectures,author,categories,copyright,description,dtpFormats,filetypesRun,filetypesSet,fonts,help,licence,maintainer,monitorDefinitionFiles,packageName,packageSection,packageVersion,printerDefinitionFiles,priority,programmingLanguages,relocatableModules,relocatableModulesDependantUpon,riscOsVers,source,territories,systemVariables,toolboxRequired,utilities]:
                            app.append(component)
                        #endfor
                        apps.append(app)
                    #endfor
                    z.close()
                else:
                    self.urlsCollection.remove({'url':url})
                    print 'Removing from urls: '+url
                    latestMessage = 'URL <a href="'+url+'">'+url+'</a> not a zip file!'
                    return apps, latestMessage
                #endif
            #endif
            try:
                os.remove(hashDataPath)
            except:
                True
        #endif
        return apps, latestMessage
    #enddef
#endclass

socket.setdefaulttimeout(30)

if __name__ == '__main__':
    riscosspider = riscosspider()
    riscosspider.continuous()
