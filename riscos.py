# The RISC OS Search Engine
# Developed by Rebecca Shalfield for The RISC OS Community
# Copyright (c) Rebecca Shalfield 2002-2013

import cherrypy, Cookie, hashlib, re, os, pymongo, riscosspider, sha, sys, time, urllib, urllib2, urlparse, zipfile
from pymongo import Connection
from bson import ObjectId
from random import randint

class riscos:

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
        
        self.mirror = 'www.shalfield.com/riscos'
        self.mirrors = ['84.92.157.78/riscos','www.shalfield.com/riscos','192.168.88.1:8081/riscos']
        
        self.months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
        
        self.blacklisted_domains = {}
        self.blacklisted_domains['edit.yahoo.com'] = ''
        self.blacklisted_domains['validator.w3.org'] = ''

        self.usualDomains = ['www.apdl.co.uk',
                             'www.drobe.co.uk',
                             'www.ebay.co.uk',
                             'www.iconbar.co.uk',
                             'www.myriscos.co.uk',
                             'www.riscosopen.org'
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
        
        self.displayedAttributes = [
                                    ('Computer','computer',''),
                                    ('Podule','podule',''),
                                    ('Application Name','application_name','app.png'),
                                    ('Directory','directory','app.png'),
                                    ('Application Version','application_version',''),
                                    ('Dealer','dealer',''),
                                    ('Book','book',''),
                                    ('Contact','contact',''),
                                    ('Event','event',''),
                                    ('Glossary Term','glossary_term',''),
                                    ('Glossary Definition','glossary_definition',''),
                                    ('Question','question',''),
                                    ('Answer','answer',''),
                                    ('Developer','developer',''),
                                    ('Date','date',''),
                                    ('Authors','authors',''),
                                    ('Project','project',''),
                                    ('Purpose','purpose',''),
                                    ('Video','video',''),
                                    ('How-To','howto',''),
                                    ('Provider','provider',''),
                                    ('Magazine','magazine',''),
                                    ('Forum','forum',''),
                                    ('Error Message','error_message',''),
                                    ('Cause','cause',''),
                                    ('Solution','solution',''),
                                    ('Key Stage','key_stage',''),
                                    ('User Group','user_group',''),
                                    ('Description','description',''),
                                    ('Publisher','publisher',''),                            
                                    ('Filetypes Run','filetypes_run',''),
                                    ('Filetypes Set','filetypes_set',''),
                                    ('Absolutes','absolutes','ff8.png'),
                                    ('Utilities','utilities','ffc.png'),
                                    ('Relocatable Modules','relocatable_modules','ffa.png'),
                                    ('Module Dependencies','module_dependencies','ffa.png'),
                                    ('Programming Languages','programming_languages',''),
                                    ('Fonts','fonts','ff6.png'),
                                    ('Help','help','help.png'),
                                    ('DTP Formats','dtp_formats',''),
                                    ('RISC OS Versions','riscos_versions',''),
                                    ('Monitor Definition Files','monitor_definition_files','display.png'),
                                    ('Printer Definition Files','printer_definition_files',''),
                                    ('SoftWare Interrupt','software_interrupt',''),
                                    ('* Command','star_command',''),
                                    ('System Variables','system_variables',''),
                                    ('Identifier','identifier',''),
                                    ('Territories','territories',''),
                                    ('Source','source',''),
                                    ('Pricing','pricing',''),
                                    ('Address','address',''),
                                    ('Email','email',''),
                                    ('Telephone','telephone',''),
                                    ('Copyright','copyright',''),
                                    ('Licence','licence',''),
                                    ('Package Name','package_name','package.png'),
                                    ('Package Section','package_section',''),
                                    ('Package Version','package_version',''),
                                    ('Categories','categories',''),
                                    ('Maintainer','maintainer',''),
                                    ('Priority','priority',''),
                                    ('Page Title','page_title',''),
                                    ('Syndicated Feed Item Title','syndicated_feed_item_title',''),
                                    ('Syndicated Feed Item Description','syndicated_feed_item_description',''),
                                    ('Syndicated Feed','syndicated_feed',''),
                                    ('URL','url',''),
                                    ('Parent URL','parent_url',''),
                                    ('Last Scanned','last_scanned',''),
                                    ('Next Scan','next_scan','')
                                    ]        
        
        self.searchableAttributes = [
                                     ('Absolutes','absolutes','The name of an ARM code file'),
                                     ('Application Name','application_name','The textual name of an application'),
                                     ('Application Version','application_version','The version of an application'),
                                     ('ARC File','arc_file','A legacy Acorn archive file format with a .arc extension'),
                                     # ARM Architectures is absent as set in filter
                                     ('Authors','authors','The author of an application or book'),
                                     ('Book','book','The title of a RISC OS-related book'),
                                     ('Categories','categories','The category to which an application has been assigned within a package'),
                                     ('Computer','computer','An ARM-powered computer capable of running RISC OS natively'),
                                     ('Contact','contact','The individual to contact at a RISC OS dealer or developer'),
                                     ('Copyright','copyright','An application\'s copyright message'),
                                     ('Date','date','The date of an application'),
                                     ('Dealer','dealer',"The name of a RISC OS dealer"),
                                     ('Description','description','The description of an application or book'),
                                     ('Developer','developer',"The name of a RISC OS hardware or software developer"),
                                     ('Directory','directory','The name of a directory containing an application'),
                                     ('Domain','domain',"A web site's domain name"),
                                     ('DTP Formats','dtp_formats','Any desktop publishing files utilised within an application'),
                                     ('Error Message','error_message','Cause and potential solution for a RISC OS error message'),
                                     ('Event','event','The title of a RISC OS-related event'),
                                     ('Question','question','A frequently asked question about RISC OS'),
                                     ('Filetypes Run','filetypes_run','The filetypes runnable by an application'),
                                     ('Filetypes Set','filetypes_set','The filetypes set by an application'),
                                     ('Fonts','fonts','Any fonts defined within an application'),
                                     ('Forum','forum','The name of a RISC OS-related forum'),
                                     ('How-To','howto','How to do a task on RISC OS'),
                                     ('Glossary Term','glossary_term','A term in the RISC OS Glossary'),
                                     ('Glossary Definition','glossary_definition','The meaning of a term in the RISC OS Glossary'),
                                     ('Help','help','The contents of the !Help file found within an application directory'),
                                     ('Identifier','identifier','The ISBN or ISSN of a RISC OS-related book or magazine respectively'),
                                     ('Key Stage','key_stage','The key stage that a piece of RISC OS software is assigned to'),
                                     ('Licence','licence','The application\'s licence type'),
                                     ('Magazine','magazine','The title of a RISC OS-related magazine'),
                                     ('Maintainer','maintainer','The maintainer for a package'),
                                     ('Module Dependencies','module_dependencies','Modules an application is dependant upon'),
                                     ('Monitor Definition Files','monitor_definition_files','The driver for a monitor'),
                                     ('Package Name','package_name','The name of a package'),
                                     ('Package Section','package_section','The section for a package'),
                                     ('Package Version','package_version','The version of a package'),
                                     ('Page Title','page_title','The title of an HTML page as extracted from within the title tag'),
                                     ('Podule','podule','An expansion card for a RISC OS computer'),
                                     ('Portable Document Format File','pdf_file','Adobe-format files with a .pdf extension'),
                                     ('Pricing','pricing','The pricing of a RISC OS product'),
                                     ('Printer Definition Files','printer_definition_files','The driver for a printer'),
                                     ('Priority','priority','As set by the package'),
                                     ('Programming Languages','programming_languages','The programming language(s) an application is written in'),
                                     ('Project','project','The name of a RISC OS-related project'),
                                     ('Provider','provider','The name of an entity providing a service to the RISC OS Community'),
                                     ('Publisher','publisher','The publisher of a RISC OS-related book or magazine'),
                                     ('Purpose','purpose','The purpose of an applicatiion'),
                                     ('Relocatable Modules','relocatable_modules','Modules contained within an application directory'),
                                     # RISC OS Versions is absent as set in filter
                                     ('SoftWare Interrupt','software_interrupt','The name of a SoftWare Interrupt (SWI) defined within a module'),
                                     ('* Command','star_command','The name of a * command defined within a module'),
                                     ('Source','source','The source of the package'),
                                     ('Spark File','spark_file','A legacy Acorn archive file format with a .spk extension'),
                                     ('Syndicated Feed','syndicated_feed','The URL of an RSS or Atom Feed'),
                                     ('Syndicated Feed Item Description','syndicated_feed_item_description','The description associated with an RSS or Atom Feed item'),
                                     ('Syndicated Feed Item Title','syndicated_feed_item_title','The title of an RSS or Atom Feed item'),
                                     ('System Variables','system_variables','Environment variables set by an application'),
                                     ('User Group','user_group','The name of a RISC OS-related user group'),
                                     ('Utilities','utilities','The name of a utility'),
                                     ('Video','video','The name of a RISC OS-related video'),
                                     ('ZIP File','zip_file','The name of a .zip file, the format for the RISC OS Packaging Project')
                                     ]
        
        self.riscOsVersions = [('5.00','5.00')]
        osvers = []
        documents = self.riscosCollection.find({'module_dependencies.name':'UtilityModule'})
        for document in documents:
            for item in document['module_dependencies']:
                if item.has_key('name') and item['name'] == 'UtilityModule':
                    if item.has_key('version') and item['version'] and len(item['version']) == 4 and not item['version'] in osvers:
                        osvers.append(item['version'])
                    #endif
                #endif
            #endfor
        #endfor
        osvers.sort()
        for osver in osvers:
            if not (osver,osver) in self.riscOsVersions:
                self.riscOsVersions.append((osver,osver))
            #endif
        #endfor
        self.riscOsVersions.sort()
        
        self.territories = ['English']
        for document in self.riscosCollection.find({'territories':{"$exists":True}}):
            if document.has_key('territories'):
                for item in document['territories']:
                    if not item in self.territories:
                        self.territories.append(item)
                    #endif
                #endfor
            #endif                
        #endfor
        self.territories.sort()
                   
        self.armArchitectures = [('ARMv2','Acorn Archimedes'),
                                 ('ARMv3','Acorn RiscPC 600, Acorn RiscPC 700, Acorn A7000, Acorn A7000+'),
                                 ('ARMv4','StrongARM RiscPC, A9Home, Omega'),
                                 ('ARMv5','Iyonix'),
                                 ('ARMv6','Raspberry Pi (ARM11-based)'),
                                 ('ARMv7','BeagleBoard, Panda, Cortex-A8')
                                ]
                   
        self.romModules = [('2.00',[('UtilityModule','2.00')
                                   ]),
                           ('3.00',[('UtilityModule','3.00')
                                   ]),
                           ('3.10',[('UtilityModule','3.10')
                                   ]),
                           ('3.11',[('UtilityModule','3.11')
                                   ]),
                           ('3.50',[('UtilityModule','3.50')
                                   ]),
                           ('3.60',[('UtilityModule','3.60')
                                   ]),
                           ('3.70',[('UtilityModule','3.70')
                                   ]),
                           ('4.02',[('UtilityModule','4.02')
                                   ]),
                           ('4.39',[('UtilityModule','4.39')
                                   ]),
                           ('5.18',[('UtilityModule','5.18')
                                   ]),
                           ('6.20',[('UtilityModule','6.20')
                                   ])
                          ]
                
        try:
            print 'Ensuring '+str(len(self.searchableAttributes))+' indexes have been created...'
            for (externalAttribute,internalAttribute,key) in self.searchableAttributes:
                self.riscosCollection.ensure_index(internalAttribute)
            #endfor
        except:
            print 'ERROR: TOO MANY INDEXES!'
            self.riscosCollection.drop_indexes()
                
        # Connect to 'users' collection
        self.usersCollection = db['users']
        
        self.path = os.path.dirname(os.path.abspath(__file__))
        
        self.cookie = Cookie.SimpleCookie()
        self.sessionId = ""
        
        self.trusted_domains = {}
        
        self.riscosspider = riscosspider.riscosspider()
        
        self.periodMonth = 2419200
        self.periodYear = 31536000
        
        self.taxonomy = [['Anti-Virus','(?i)anti-virus'],
                         ['Artificial Intelligence','Expert Systems','(?i)expert system|observess'],
                         ['Artificial Intelligence','Programmming Languages','(?i)lisp|prolog'],
                         ['Business','Accounting','(?i)tax|accounting'],
                         ['Business','Personnel','(?i)personnel'],
                         ['Business','Presentation Graphics','(?i)presentation|OHP'],
                         ['Business','Project Planning','(?i)project planning'],
                         ['Business','Spreadsheets','(?i)spreadsheet|eureka|resultz'],
                         ['Business','Stock Control','(?i)stock control'],
                         ['Business','Time Management','(?i)time management'],
                         ['Command Line','(?i)command line|cli'],
                         ['Compression/Archive','(?i)spark|sparkplug|zip'],
                         ['Connectivity and Control','Communications','(?i)communication'],
                         ['Connectivity and Control','Control','(?i)control'],
                         ['Connectivity and Control','Robots','(?i)robot'],
                         ['Connectivity and Control','Turtles','(?i)turtle'],
                         ['Connectivity and Control','Networking','(?i)network'],
                         ['Education','Administration','(?i)admin'],
                         ['Education','Subjects','Art','(?i)art|paint|painting'],
                         ['Education','Subjects','Business Studies','(?i)business studies'],
                         ['Education','Subjects','Citizenship','(?i)citizenship'],
                         ['Education','Subjects','Classics','(?i)classics'],
                         ['Education','Subjects','Design and Technology','(?i)design|technology'],
                         ['Education','Subjects','Drama','(?i)drama'],
                         ['Education','Subjects','English','(?i)english'],
                         ['Education','Subjects','Geography','(?i)geography'],
                         ['Education','Subjects','History','(?i)history'],
                         ['Education','Subjects','Humanities','(?i)humanity'],
                         ['Education','Subjects','ICT','(?i)ICT'],
                         ['Education','Subjects','Mathematics','(?i)mathematics|maths|lispcalc'],
                         ['Education','Subjects','Modern Languages','(?i)modern language'],
                         ['Education','Subjects','Modern Studies','(?i)modern studies'],
                         ['Education','Subjects','Music','(?i)music|maestro'],
                         ['Education','Subjects','Physical Education','(?i)physical education'],
                         ['Education','Subjects','Religious Education','(?i)religious education|religion|bible'],
                         ['Education','Subjects','Sciences','(?i)science|physics|biology|chemistry'],
                         ['Education','Subjects','Technology','(?i)technology'],
                         ['Emulation','(?i)emulator|emulation'],
                         ['Freeware','(?i)freeware'],
                         ['Graphics','Animation','(?i)animation|animate'],
                         ['Graphics','Art','(?i)art'],
                         ['Graphics','Computer-Aided Design','(?i)CAD|computer-aided design|draw'],
                         ['Graphics','Conversion','(?i)changefsi'],
                         ['Graphics','Data Presentation','(?i)data presentation'],
                         ['Graphics','Graphics Libraries','(?i)graphics library'],
                         ['Graphics','Image Processing','(?i)image processing'],
                         ['Graphics','Ray Tracing','(?i)ray tracing'],
                         ['Graphics','Scanning and Digitising','(?i)scanning|digitising'],
                         ['Graphics','Video Post-Processing','(?i)video'],
                         ['Information Storage and Retrieval','Database Management Systems','(?i)database management system|datapower'],
                         ['Information Storage and Retrieval','Data Files','(?i)data file'],
                         ['Information Storage and Retrieval','Full Text Database Systems','(?i)full text database system'],
                         ['Information Storage and Retrieval','Hypermedia','(?i)hypermedia|magpie'],
                         ['Information Storage and Retrieval','Library Management Systems','(?i)library management system'],
                         ['Information Storage and Retrieval','Specialised Data Management Systems','(?i)specialised data management system'],
                         ['Information Storage and Retrieval','Videotex Database Systems','(?i)videotex database system'],
                         ['Information Storage and Retrieval','Classification Schemes','(?i)classification scheme'],
                         ['Leisure and Entertainment','Games','(?i)game'],
                         ['Leisure and Entertainment','Hobbies','(?i)hobby'],
                         ['Medicine and Health','Health Administration','(?i)health admin'],
                         ['Medicine and Health','Healthcare','(?i)healthcare'],
                         ['Medicine and Health','Health Education','(?i)health education'],
                         ['Medicine and Health','Medical Records','(?i)medical record'],
                         ['Medicine and Health','Monitoring','(?i)health monitoring'],
                         ['Medicine and Health','Therapeutics','(?i)therapeutic'],
                         ['Medicine and Health','Psychology','(?i)psychology'],
                         ['Medicine and Health','Nursing','(?i)nursing'],
                         ['Network','Internet','Email','(?i)messenger|email client|pluto'],
                         ['Network','Internet','FTP','(?i)ftpc'],
                         ['Network','Internet','General','(?i)ping|sunfish'],
                         ['Network','Internet','Usenet','(?i)newshound'],
                         ['Network','Internet','Terminal','(?i)nettle'],
                         ['Network','Internet','Web Broswer','(?i)netsurf|arcweb'],
                         ['Network','Internet','Web Server','(?i)serviette'],
                         ['Peripherals','CD-ROM','(?i)cd-rom'],
                         ['Peripherals','DVD','(?i)dvd'],
                         ['Peripherals','Expansion Cards','(?i)expansion card|podule'],
                         ['Peripherals','Firmware','(?i)firmware'],
                         ['Peripherals','Input Devices','(?i)input device|keyboard|mouse'],
                         ['Peripherals','Keyboards','(?i)keyboard'],
                         ['Peripherals','Memory','(?i)memory|ram'],
                         ['Peripherals','Memory Cards','(?i)memory card'],
                         ['Peripherals','Mice','(?i)mouse'],
                         ['Peripherals','Network Cards','(?i)network card|NCI'],
                         ['Peripherals','Output Devices','(?i)output device'],
                         ['Peripherals','Printers','(?i)printer'],
                         ['Peripherals','Storage Devices','(?i)storage device'],
                         ['Peripherals','USB','(?i)usb'],
                         ['Programming','Languages','ADA','ADA'],
                         ['Programming','Languages','Assembler','(?i)assembler'],
                         ['Programming','Languages','BBC BASIC','BBC BASIC'],
                         ['Programming','Languages','C/C++','(?i)c/c\+\+|ansi c|desktop c'],
                         ['Programming','Languages','COBOL','(?i)cobol'],
                         ['Programming','Languages','Lisp','(?i)lisp'],
                         ['Programming','Languages','Modula-2','(?i)module-2'],
                         ['Programming','Languages','Pascal','(?i)pascal'],
                         ['Programming','Languages','Prolog','(?i)prolog'],
                         ['Programming','Languages','Python','(?i)python'],
                         ['Programming','Languages','General','(?i)programming'],
                         ['Publications','(?i)publication|arcscan'],
                         ['Public Domain','(?i)public domain'],
                         ['Science and Industry','Data Capture/Logging','(?i)data capture|data logging'],
                         ['Science and Industry','Engineering','(?i)engineering'],
                         ['Science and Industry','Industrial Applications','(?i)industrial'],
                         ['Science and Industry','Scientific Research','(?i)scientific research'],
                         ['Shareware','(?i)shareware'],
                         ['Sound and Music','(?i)sound|music'],
                         ['Text Processing','Desktop Publishing','(?i)desktop publishing|ovation|impression'],
                         ['Text Processing','Fonts','(?i)font'],
                         ['Text Processing','Spell Checkers and Word Finders','(?i)spell(?:ing)? check|word find'],
                         ['Text Processing','Text Editors','(?i)text editor'],
                         ['Text Processing','Word Processing','(?i)word processing|word processor|easiwriter'],
                         ['Text Processing','Optical Character Recognition','(?i)optical character recognition|OCR'],
                         ['Video','(?i)video'],
                         ['General','CD-ROM Discs','(?i)CD-ROM'],
                         ['General','Demos','(?i)demo'],
                         ['General','Personal Productivity','(?i)personal productivity'],
                         ['Upgrades','Firmware','(?i)firmware'],
                         ['Utilities','(?i)utility']
                        ]
    #enddef

    @cherrypy.expose
    def rescan(self, doc_id, origin):
        status = self.cookie_handling()
        if doc_id:
            if self.riscosCollection.find({'_id':ObjectId(doc_id)}).count():
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document.has_key('url') and document['url']:
                    userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
                    if userDocument:
                        rescanAllowed = True
                        if userDocument.has_key('rescan_count') and userDocument['rescan_count'] and userDocument['rescan_count'] >= 10:
                            rescanAllowed = False
                        #endif
                        if rescanAllowed:
                            url = document['url']
                            count = self.urlsCollection.find({'url':url}).count()
                            if not count:
                                movedDocument = {}
                                movedDocument['url'] = url
                                movedDocument['last_scanned'] = 0
                                if url.lower().endswith('.zip'):
                                    movedDocument['zip_file'] = url
                                #endif
                                self.urlsCollection.insert(movedDocument)
                            #endif
                            self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                            if userDocument:
                                if userDocument.has_key('rescan_count') and userDocument['rescan_count']:
                                    userDocument['rescan_count'] += 1
                                else:
                                    userDocument['rescan_count'] = 1
                                #endif
                                self.usersCollection.save(userDocument)
                            #endif
                        #endif
                    #endif
                #endif
            #endif
        #endif
        raise cherrypy.HTTPRedirect("/riscos/"+origin, 302)
    #enddef

    @cherrypy.expose
    def namespace(self):
        content = ""
        # Placeholder page for XML Namespace
        return content
    #enddef
    
    @cherrypy.expose
    def add_to_watchlist(self, doc_id, origin, nested=False):
        status = self.cookie_handling()
        if doc_id:
            if self.riscosCollection.find({'_id':ObjectId(doc_id)}).count():
                userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
                if userDocument.has_key('watchlist'):
                    userDocument['watchlist'].append(doc_id)
                else:
                    userDocument['watchlist'] = [doc_id]
                #endif
                self.usersCollection.save(userDocument)
            #endif
        #endif
        if origin == 'advanced_search':
            if nested:
                raise cherrypy.HTTPRedirect("/riscos/advanced_search?nested=true", 302)
            else:
                raise cherrypy.HTTPRedirect("/riscos/advanced_search", 302)
            #endif
        else:
            raise cherrypy.HTTPRedirect("/riscos/"+origin, 302)
        #endif
    #enddef
    
    def insert_url_into_rejects(self, url):
        epoch = int(time.time())
        rejectDocument = {}
        rejectDocument['url'] = url
        rejectDocument['last_scanned'] = epoch
        self.rejectsCollection.insert(rejectDocument)
        print 'Inserting into rejects: '+url     
    #enddef
    
    @cherrypy.expose
    def record_as_json(self, doc_id=""):
        if doc_id:
            content = ""
            status = self.cookie_handling()
            content += self.header(status, 'index, nofollow')
            content += '<h2>Record in JSON Format</h2>'
            if self.riscosCollection.find({'_id':ObjectId(doc_id)}).count():
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    content += '<p class="json">'
                    content += self.dictionary_as_json(document, 0)
                    content += '</p>'
                #endif
            #endif
            content += self.footer()
            return content
        else:
            raise cherrypy.HTTPRedirect("/riscos/index", 302)
        #endif    
    #enddef
    
    def dictionary_as_json(self, dictionary, indent):
        if dictionary.has_key('_id'):
            del dictionary['_id']
        #endif
        content = ""
        indentString = ""
        for indentCount in range(indent):
            indentString += '&nbsp;'
        #endfor
        content += indentString + '{<br>'
        numberOfKeys = len(dictionary.keys())
        keyCount = 0
        for key in dictionary.keys():
            if key != '_id':
                keyCount += 1
                content += self.key_value_pair_as_json(numberOfKeys, keyCount, key, dictionary[key], indent+4)
            #endif
        #endfor                    
        content += indentString + '}'
        return content                    
    #enddef
    
    def key_value_pair_as_json(self, numberOfKeys, keyCount, key, value, indent):
        content = ""
        indentString = ""
        for indentCount in range(indent):
            indentString += '&nbsp;'
        #endfor
        content += indentString + '"<b class="key">'+key+'</b>": '
        if isinstance(value,dict):
            content += '<b class="dictionary">'+str(value)+'</b>'
        elif isinstance(value,float):
            content += '<b class="float">'+str(value)+'</b>'
        elif isinstance(value,int):
            content += '<b class="integer">'+str(value)+'</b>'
        elif isinstance(value,list):
            content += '[<br>'
            for i in range(len(value)):
                if isinstance(value[i],dict):
                    content += self.dictionary_as_json(value[i], indent+4)
                else:
                    content += indentString + '"<b class="string">'+str(value[i])+'</b>"'
                #endif
                if i < len(value)-1:
                    content += ','
                #endif
                content += '<br>'
            #endfor
            content += indentString + ']'
        else:
            try:        
                content += '"<b class="string">'+str(value)+'</b>"'
            except:
                content += '"<b class="string">!!!ERROR!!!</b>"'
        #endif
        if keyCount < numberOfKeys:
            content += ','
        #endif
        content += '<br>'
        return content                                
    #endif
    
    @cherrypy.expose
    def record_as_xml(self, doc_id=""):
        if doc_id:
            content = ""
            status = self.cookie_handling()
            content += self.header(status, 'index, nofollow')
            content += '<h2>Record in riscos.xml Format</h2>'
            content += '<div id="introduction">'
            if self.riscosCollection.find({'_id':ObjectId(doc_id)}).count():
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    if document.has_key('_id'):
                        del document['_id']
                    #endif
                    content += '<p align="left">'
                    xmlCode = self.dictionary_as_xml(document)
                    content += self.post_process_xml_code(xmlCode)
                    content += '</p>'
                #endif
            #endif
            content += '</div>'
            content += self.footer()
            return content
        else:
            raise cherrypy.HTTPRedirect("/riscos/index", 302)
        #endif    
    #enddef
    
    def post_process_xml_code(self, xmlCode):
        xmlCode = xmlCode.replace('<','&lt;')
        xmlCode = xmlCode.replace('>','&gt;')
        xmlCode = xmlCode.replace('  ','&nbsp;&nbsp;')
        xmlCode = xmlCode.replace('&lt;','<b class="element">&lt;')
        xmlCode = xmlCode.replace('&gt;','&gt;</b>')
        xmlCode = xmlCode.replace('\n','<br>')
        return xmlCode
    #enddef
    
    def app_as_xml(self, dictionary):
        content = ""
        if (dictionary.has_key('directory') and dictionary['directory']) or (dictionary.has_key('application_name') and dictionary['application_name']):
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            fourthIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
                fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<apps>\n'
            content += secondIndent + '<app>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'absolutes':
                        content += thirdIndent + '<absolutes>\n'
                        content += self.embedded_absolutes_as_xml(dictionary['absolutes'])
                        content += thirdIndent + '</absolutes>\n'
                    if key == 'addressing_mode':
                        if dictionary['addressing_mode'] in ['26-bit','32-bit','26/32-bit']:
                            content += thirdIndent + '<addressingMode>'+dictionary['addressing_mode']+'</addressingMode>\n'
                        #endif
                    elif key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'application_version': 
                        content += thirdIndent + '<version>'+dictionary['application_version']+'</version>\n'
                    elif key == 'arm_architectures':
                        content += thirdIndent + '<armArchitectures>\n'
                        content += self.arm_architectures_as_xml(dictionary['arm_architectures'])
                        content += thirdIndent + '</armArchitectures>\n'
                    elif key == 'authors':
                        content += thirdIndent + '<authors>\n'
                        for author in dictionary['authors']:
                            content += fourthIndent + '<author>'+author+'</author>\n'
                        #endfor
                        content += thirdIndent + '</authors>\n'
                    elif key in ['copyright','developer','directory','help','identifier','licence','maintainer','purpose','url']:
                        content += thirdIndent + '<'+key+'>'+dictionary[key]+'</'+key+'>\n'
                    elif key == 'application_name':
                        content += thirdIndent + '<name>'+dictionary['application_name']+'</name>\n'
                    elif key == 'date':
                        try:
                            timeTuple = time.localtime(int(dictionary['date']))
                            content += thirdIndent + '<released day="'+str(timeTuple[2])+'" month="'+str(timeTuple[1])+'" year="'+str(timeTuple[0])+'"/>\n'
                        except:
                            True
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'filetypes_run':
                        content += thirdIndent + '<filetypesRun>\n'
                        content += self.filetypes_run_as_xml(dictionary['filetypes_run'])
                        content += thirdIndent + '</filetypesRun>\n'
                    elif key == 'filetypes_set':
                        content += thirdIndent + '<filetypesSet>\n'
                        content += self.filetypes_set_as_xml(dictionary['filetypes_set'])
                        content += thirdIndent + '</filetypesSet>\n'
                    elif key == 'fonts':
                        content += thirdIndent + '<fonts>\n'
                        content += self.embedded_fonts_as_xml(dictionary['fonts'])
                        content += thirdIndent + '</fonts>\n'
                    elif key == 'icon_url':
                        content += thirdIndent + '<iconUrl>'+dictionary['icon_url']+'</iconUrl>\n'
                    elif key == 'image_url':
                        content += thirdIndent + '<image url="'+dictionary['image_url']+'"'
                        if dictionary.has_key('image_caption') and dictionary['image_caption']:
                            content += ' caption="'+dictionary['image_caption']+'"'
                        #endif
                        content += ' />\n'
                    elif key == 'key_stages':
                        content += thirdIndent + '<keyStages>\n'
                        content += self.keystages_as_xml(dictionary['key_stages'])
                        content += thirdIndent + '</keyStages>\n'
                    elif key == 'module_dependencies':
                        content += thirdIndent + '<moduleDependencies>\n'
                        content += self.module_dependencies_as_xml(dictionary['module_dependencies'])
                        content += thirdIndent + '</moduleDependencies>\n'
                    elif key == 'pricing':
                        content += thirdIndent + '<pricing>\n'
                        content += self.pricing_as_xml(dictionary['pricing'])
                        content += thirdIndent + '</pricing>\n'
                    elif key == 'programming_languages':
                        content += thirdIndent + '<programmingLanguages>\n'
                        content += self.programming_languages_as_xml(dictionary['programming_languages'])
                        content += thirdIndent + '</programmingLanguages>\n'
                    elif key == 'relocatable_modules':
                        content += thirdIndent + '<relocatableModules>\n'
                        content += self.embedded_relocatable_modules_as_xml(dictionary['relocatable_modules'])
                        content += thirdIndent + '</relocatableModules>\n'
                    elif key == 'system_variables':
                        content += thirdIndent + '<systemVariables>\n'
                        content += self.system_variables_as_xml(dictionary['system_variables'])
                        content += thirdIndent + '</systemVariables>\n'
                    elif key == 'territories':
                        content += thirdIndent + '<territories>\n'
                        content += self.territories_as_xml(dictionary['territories'])
                        content += thirdIndent + '</territories>\n'
                    elif key == 'utilities':
                        content += thirdIndent + '<utilities>\n'
                        content += self.embedded_utilities_as_xml(dictionary['utilities'])
                        content += thirdIndent + '</utilities>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</app>\n'
            content += firstIndent + '</apps>\n'
        #endif
        return content
    #enddef    
    
    def filetypes_run_as_xml(self, filetypesRun):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for filetypeRun in filetypesRun:
            content += fourthIndent + '<filetypeRun>'+filetypeRun+'</filetypeRun>\n'
        #endfor        
        return content
    #enddef

    def filetypes_set_as_xml(self, filetypesSet):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for filetypeSet in filetypesSet:
            content += fourthIndent + '<filetypeSet>'+filetypeSet+'</filetypeSet>\n'
        #endfor        
        return content
    #enddef     
    
    def embedded_absolutes_as_xml(self, absolutes):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for absolute in absolutes:
            content += fourthIndent + '<absolute>\n'
            content += fifthIndent + '<name>' + absolute + '</name>\n'
            content += fourthIndent + '</absolute>\n'
        #endfor        
        return content
    #enddef
    
    def arm_architectures_as_xml(self, armArchitectures):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for armArchitecture in armArchitectures:                
            armArchitecture = armArchitecture.replace('ARM','arm')
            content += fourthIndent + '<'+armArchitecture+'/>\n'
        #endfor        
        return content
    #enddef    
    
    def embedded_fonts_as_xml(self, fonts):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for font in fonts:
            content += fourthIndent + '<font>\n'
            content += fifthIndent + '<name>'+font+'</name>\n'
            content += fourthIndent + '</font>\n'
        #endfor        
        return content
    #enddef
    
    def keystages_as_xml(self, keyStages):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for keyStage in keyStages:
            content += fourthIndent + '<keyStage>'+keyStage+'</keyStage>\n'
        #endfor        
        return content
    #enddef
    
    def module_dependencies_as_xml(self, module_dependencies):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in module_dependencies:
            if isinstance(dictionary,dict):
                content += fourthIndent + '<moduleDependency>\n'
                for key in dictionary.keys():
                    if key == 'name':
                        content += fifthIndent + '<name>'+dictionary['name']+'</name>\n'
                    elif key == 'version':
                        content += fifthIndent + '<version>'+dictionary['version']+'</version>\n'
                    #endif
                #endfor
                content += fourthIndent + '</moduleDependency>\n'
            #endif
        #endfor       
        return content
    #enddef
    
    def pricing_as_xml(self, pricing):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in pricing:
            if dictionary.has_key('type') and dictionary['type']:
                price = ""
                if dictionary.has_key('price') and dictionary['price']:
                    price = dictionary['price']
                #endif
                if price:
                    currency = ""
                    if dictionary.has_key('currency') and dictionary['currency']:
                        currency = dictionary['currency']
                    #endif
                    if dictionary['type'] == 'ebook':
                        content += fourthIndent + '<ebook'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</ebook>\n'
                    elif dictionary['type'] == 'hardback':
                        content += fourthIndent + '<hardback'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</hardback>\n'
                    elif dictionary['type'] == 'hourly':
                        content += fourthIndent + '<hourly'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</hourly>\n'
                    elif dictionary['type'] == 'issue':
                        content += fourthIndent + '<issue'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</issue>\n'
                    elif dictionary['type'] == 'single':
                        content += fourthIndent + '<single'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</single>\n'
                    elif dictionary['type'] == 'singleuser':
                        content += fourthIndent + '<singleuser'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</singleuser>\n'                    
                    elif dictionary['type'] == 'sitelicence':
                        content += fourthIndent + '<sitelicence'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</sitelicence>\n'
                    if dictionary['type'] == 'softback':
                        content += fourthIndent + '<softback'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</softback>\n'                        
                    elif dictionary['type'] == 'subscription':
                        duration = ""
                        if dictionary.has_key('duration') and dictionary['duration']:
                            duration = dictionary['duration']
                        #endif
                        content += fourthIndent + '<subscription'
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        if duration:
                            content += ' duration="'+duration+'"'
                        #endif
                        content += '>'+price+'</subscription>\n'
                    elif dictionary['type'] == 'upgrade':
                        upgradeFrom = ""
                        upgradeTo = ""
                        if dictionary.has_key('from') and dictionary['from']:
                            upgradeFrom = dictionary['from']
                        #endif
                        if dictionary.has_key('to') and dictionary['to']:
                            upgradeTo = dictionary['to']
                        #endif
                        content += fourthIndent + '<upgrade'
                        if upgradeTo:
                            content += ' to="'+upgradeTo+'"'
                        #endif
                        if upgradeFrom:
                            content += ' from="'+upgradeFrom+'"'
                        #endif
                        if currency:
                            content += ' currency="'+currency+'"'
                        #endif
                        content += '>'+price+'</upgrade>\n'
                    #endif
                #endif
            #endif
        #endfor       
        return content
    #enddef    
    
    def programming_languages_as_xml(self, programmingLanguages):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for programmingLanguage in programmingLanguages:
            content += fourthIndent + '<programmingLanguage>'+programmingLanguage+'</programmingLanguage>\n'
        #endfor        
        return content
    #enddef
    
    def interrupts_as_xml(self, interrupts):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for interrupt in interrupts:
            content += fourthIndent + '<interrupt>'+interrupt+'</interrupt>\n'
        #endfor        
        return content
    #enddef
    
    def related_commands_as_xml(self, relatedCommands):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for relatedCommand in relatedCommands:
            content += fourthIndent + '<relatedCommand>'+relatedCommand+'</relatedCommand>\n'
        #endfor        
        return content
    #enddef
    
    def related_vectors_as_xml(self, relatedVectors):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for relatedVector in relatedVectors:
            content += fourthIndent + '<relatedVector>'+relatedVector+'</relatedVector>\n'
        #endfor        
        return content
    #enddef
    
    def related_swis_as_xml(self, relatedSwis):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for relatedSwi in relatedSwis:
            content += fourthIndent + '<relatedSwi>'+relatedSwi+'</relatedSwi>\n'
        #endfor        
        return content
    #enddef
    
    def software_interrupts_as_xml(self, softwareInterrupts):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in softwareInterrupts:
            content += fourthIndent + '<softwareInterrupt>\n'
            for key in dictionary:
                if key == 'hex_number':
                    content += fifthIndent + '<hexNumber>'+dictionary['hex_number']+'</hexNumber>\n'
                elif key == 'interrupts':
                    content += fifthIndent + '<interrupts>\n'
                    content += self.interrupts_as_xml(dictionary['interrupts'])
                    content += fifthIndent + '</interrupts>\n'
                elif key == 'name':
                    if dictionary.has_key('reason_code') and dictionary['reason_code']:
                        content += fifthIndent + '<name reasonCode="'+dictionary['reason_code']+'">'+dictionary['name']+'</name>\n'
                    else:
                        content += fifthIndent + '<name>'+dictionary['name']+'</name>\n'
                    #endif
                elif key == 'on_entry':
                    content += fifthIndent + '<onEntry>\n'
                    content += self.on_entry_as_xml(dictionary['on_entry'])
                    content += fifthIndent + '</onEntry>\n' 
                elif key == 'on_exit':
                    content += fifthIndent + '<onExit>\n'
                    content += self.on_exit_as_xml(dictionary['on_exit'])
                    content += fifthIndent + '</onExit>\n'
                elif key == 'processor_mode':
                    content += fifthIndent + '<processorMode>'+dictionary['processor_mode']+'</processorMode>\n'
                elif key == 'reason_code':
                    content += fifthIndent + '<reasonCode>'+dictionary['reason_code']+'</reasonCode>\n'
                elif key == 're_entrancy':
                    content += fifthIndent + '<reEntrancy>'+dictionary['re_entrancy']+'</reEntrancy>\n'
                elif key == 'related_swis':
                    content += fifthIndent + '<relatedSwis>\n'
                    content += self.related_swis_as_xml(dictionary['related_swis'])
                    content += fifthIndent + '</relatedSwis>\n'
                elif key == 'related_vectors':
                    content += fifthIndent + '<relatedVectors>\n'
                    content += self.related_vectors_as_xml(dictionary['related_vectors'])
                    content += fifthIndent + '</relatedVectors>\n'
                elif key == 'summary':
                    content += fifthIndent + '<summary>'+dictionary['summary']+'</summary>\n'
                elif key == 'use':
                    content += fifthIndent + '<use>'+dictionary['use']+'</use>\n'
                #endif
            #endfor
            content += fourthIndent + '</softwareInterrupt>\n'
        #endfor       
        return content
    #enddef     
    
    def star_commands_as_xml(self, star_commands):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in star_commands:
            content += fourthIndent + '<starCommand>\n'
            for key in dictionary:
                if key == 'example':
                    content += fifthIndent + '<example>'+dictionary['example']+'</example>\n'
                elif key == 'name':
                    content += fifthIndent + '<name>'+dictionary['name']+'</name>\n'
                elif key == 'parameters':
                    content += fifthIndent + '<parameters>\n'
                    content += self.parameters_as_xml(dictionary['parameters'])
                    content += fifthIndent + '</parameters>\n'
                elif key == 'related_commands':
                    content += fifthIndent + '<relatedCommands>\n'
                    content += self.related_commands_as_xml(dictionary['related_commands'])
                    content += fifthIndent + '</relatedCommands>\n'
                elif key == 'summary':
                    content += fifthIndent + '<summary>'+dictionary['summary']+'</summary>\n'
                elif key == 'syntax':
                    content += fifthIndent + '<syntax>'+dictionary['syntax']+'</syntax>\n'
                elif key == 'use':
                    content += fifthIndent + '<use>'+dictionary['use']+'</use>\n'
                #endif
            #endfor
            content += fourthIndent + '</starCommand>\n'
        #endfor       
        return content
    #enddef 
    
    def embedded_relocatable_modules_as_xml(self, relocatableModules):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        sixthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            sixthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for relocatableModule in relocatableModules:
            content += fourthIndent + '<relocatableModule>\n'
            for key in relocatableModule:
                if key == 'addressing_mode':
                    if relocatableModule['addressing_mode'] in ['26-bit','32-bit','26/32-bit']:
                        content += fifthIndent + '<addressingMode>'+relocatableModule['addressing_mode']+'</addressingMode>\n'
                    #endif
                elif key == 'name':
                    content += fifthIndent + '<name>'+relocatableModule['name']+'</name>\n'
                elif key == 'software_interrupts':
                    content += fifthIndent + '<softwareInterrupts>\n'
                    content += self.software_interrupts_as_xml(dictionary['software_interrupts'])
                    content += fifthIndent + '</softwareInterrupts>\n'    
                elif key == 'star_commands':
                    content += fifthIndent + '<starCommands>\n'
                    content += self.star_commands_as_xml(dictionary['star_commands'])
                    content += fifthIndent + '</starCommands>\n'
                elif key == 'version':
                    content += fifthIndent + '<version>'+relocatableModule['version']+'</version>\n'
                #endif
            #endfor
            content += fourthIndent + '</relocatableModule>\n'
        #endfor        
        return content
    #enddef
    
    def on_entry_as_xml(self, onEntry):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in onEntry:
            number = ""
            description = ""
            for key in dictionary:
                if key == 'number':
                    number = dictionary['number']
                elif key == 'description':
                    description = dictionary['description']
                #endif
            #endfor
            content += fourthIndent + '<register number="'+number+'" description="'+description+'" />\n'
        #endfor        
        return content
    #enddef
    
    def on_exit_as_xml(self, onExit):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in onExit:
            number = ""
            description = ""
            for key in dictionary:
                if key == 'number':
                    number = dictionary['number']
                elif key == 'description':
                    description = dictionary['description']
                #endif
            #endfor
            content += fourthIndent + '<register number="'+number+'" description="'+description+'" />\n'
        #endfor        
        return content
    #enddef
    
    def parameters_as_xml(self, parameters):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for dictionary in parameters:
            name = ""
            description = ""
            for key in dictionary:
                if key == 'name':
                    name = dictionary['name']
                elif key == 'description':
                    description = dictionary['description']
                #endif
            #endfor
            content += fourthIndent + '<parameter name="'+name+'" description="'+description+'" />\n'
        #endfor        
        return content
    #enddef 
    
    def embedded_utilities_as_xml(self, utilities):
        content = ""
        fourthIndent = ""
        fifthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            fifthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for utility in utilities:
            content += fourthIndent + '<utility>\n'
            for key in utility:
                if key == 'name':
                    content += fifthIndent + '<name>'+utility['name']+'</name>\n'
                elif key == 'syntax':
                    content += fifthIndent + '<syntax>'+utility['syntax']+'</syntax>\n'
                elif key == 'version':
                    content += fifthIndent + '<version>'+utility['version']+'</version>\n'
                #endif
            #endfor
            content += fourthIndent + '</utility>\n'
        #endfor        
        return content
    #enddef
    
    def system_variables_as_xml(self, systemVariables):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for systemVariable in systemVariables:
            content += fourthIndent + '<systemVariable>'+systemVariable+'</systemVariable>\n'
        #endfor        
        return content
    #enddef    
    
    def territories_as_xml(self, territories):
        content = ""
        fourthIndent = ""
        for indentCount in range(4):
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        for territory in territories:
            content += fourthIndent + '<territory>'+territory+'</territory>\n'
        #endfor        
        return content
    #enddef
    
    def peripheral_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('peripheral') and dictionary['peripheral']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            fourthIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
                fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<peripherals>\n'
            content += secondIndent + '<peripheral>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'peripheral':
                        content += thirdIndent + '<name>'+dictionary['peripheral']+'</name>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'device_type':
                        content += thirdIndent + '<deviceType>'+dictionary['device_type']+'</deviceType>\n'
                    elif key in ['developer','identifier','url']:
                        content += thirdIndent + '<'+key+'>'+dictionary[key]+'</'+key+'>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</peripheral>\n'
            content += firstIndent + '</peripherals>\n'
        #endif
        return content
    #enddef

    def podule_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('podule') and dictionary['podule']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            fourthIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
                fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<podules>\n'
            content += secondIndent + '<podule>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'podule':
                        content += thirdIndent + '<name>'+dictionary['podule']+'</name>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key in ['developer','identifier','url']:
                        content += thirdIndent + '<'+key+'>'+dictionary[key]+'</'+key+'>\n'
                    elif key == 'pricing':
                        content += thirdIndent + '<pricing>\n'
                        content += self.pricing_as_xml(dictionary['pricing'])
                        content += thirdIndent + '</pricing>\n'
                    elif key == 'relocatable_modules':
                        content += thirdIndent + '<relocatableModules>\n'
                        content += self.embedded_relocatable_modules_as_xml(dictionary['relocatable_modules'])
                        content += thirdIndent + '</relocatableModules>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</podule>\n'
            content += firstIndent + '</podules>\n'
        #endif
        return content
    #enddef     
    
    def anniversary_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('anniversary') and dictionary['anniversary']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            fourthIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
                fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<anniversaries>\n'
            content += secondIndent + '<anniversary>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'anniversary':
                        content += thirdIndent + '<title>'+dictionary['anniversary']+'</title>\n'
                    elif key == 'date':
                        timeTuple = time.localtime(int(dictionary['date']))
                        content += thirdIndent + '<date day="'+str(timeTuple[2])+'" month="'+str(timeTuple[1])+'" year="'+str(timeTuple[0])+'"/>\n' 
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'url':
                        content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</anniversary>\n'
            content += firstIndent + '</anniversaries>\n'
        #endif
        return content
    #enddef
    
    def book_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('book') and dictionary['book']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            fourthIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
                fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<books>\n'
            content += secondIndent + '<book>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'book':
                        content += thirdIndent + '<title>'+dictionary['book']+'</title>\n'
                    elif key == 'authors':
                        content += thirdIndent + '<authors>\n'
                        for author in dictionary['authors']:
                            content += fourthIndent + '<author>'+author+'</author>\n'
                        #endfor
                        content += thirdIndent + '</authors>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'image_url':
                        content += thirdIndent + '<image url="'+dictionary['image_url']+'"'
                        if dictionary.has_key('image_caption') and dictionary['image_caption']:
                            content += ' caption="'+dictionary['image_caption']+'"'
                        #endif
                        content += ' />\n'
                    elif key == 'identifier':
                        content += thirdIndent + '<isbn>'+dictionary['identifier']+'</isbn>\n'
                    elif key == 'pricing':
                        content += thirdIndent + '<pricing>\n'
                        content += self.pricing_as_xml(dictionary['pricing'])
                        content += thirdIndent + '</pricing>\n'
                    elif key == 'publisher':
                        content += thirdIndent + '<publisher>'+dictionary['publisher']+'</publisher>\n'
                    elif key == 'date':
                        timeTuple = time.localtime(int(dictionary['date']))
                        content += thirdIndent + '<published day="'+str(timeTuple[2])+'" month="'+str(timeTuple[1])+'" year="'+str(timeTuple[0])+'"/>\n'  
                    elif key == 'url':
                        content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</book>\n'
            content += firstIndent + '</books>\n'
        #endif
        return content
    #enddef
    
    def computer_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('computer') and dictionary['computer']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<computers>\n'
            content += secondIndent + '<computer>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'computer':
                        content += thirdIndent + '<name>'+dictionary['computer']+'</name>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'developer':
                        content += thirdIndent + '<developer>'+dictionary['developer']+'</developer>\n'
                    elif key == 'identifier':
                        content += thirdIndent + '<identifier>'+dictionary['identifier']+'</identifier>\n'
                    elif key == 'pricing':
                        content += thirdIndent + '<pricing>\n'
                        content += self.pricing_as_xml(dictionary['pricing'])
                        content += thirdIndent + '</pricing>\n'
                    elif key == 'url':
                        content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</computer>\n'
            content += firstIndent + '</computers>\n'
        #endif
        return content
    #enddef
    
    def dealer_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('dealer') and dictionary['dealer']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<dealers>\n'
            content += secondIndent + '<dealer>\n'
            for key in dictionary.keys():
                if key == 'advert_url':
                    content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                elif key == 'dealer':
                    content += thirdIndent + '<name>'+dictionary['dealer']+'</name>\n'
                elif key == 'description':
                    if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                        content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                    else:
                        content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                    #endif
                elif key in ['address','contact','email','telephone','url']:
                    content += thirdIndent + '<'+key+'>'+dictionary[key]+'</'+key+'>\n'
                #endif
            #endfor
            content += secondIndent + '</dealer>\n'
            content += firstIndent + '</dealers>\n'
        #endif
        return content
    #enddef
    
    def error_message_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('error_message') and dictionary['error_message']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<errorMessages>\n'
            content += secondIndent + '<errorMessage>\n'
            for key in dictionary.keys():
                if key == 'cause':
                    content += thirdIndent + '<cause>'+dictionary['cause']+'</cause>\n'
                elif key.lower() == 'error_message':
                    content += thirdIndent + '<message>'+dictionary['error_message']+'</message>\n'
                elif key == 'solution':
                    content += thirdIndent + '<solution>'+dictionary['solution']+'</solution>\n'
                #endif
            #endfor
            content += secondIndent + '</errorMessage>\n'
            content += firstIndent + '</errorMessages>\n'
        #endif
        return content
    #enddef
    
    def event_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('event') and dictionary['event']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<events>\n'
            content += secondIndent + '<event>\n'
            if dictionary.has_key('advert_url') and dictionary['advert_url']:
                content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
            #endif
            if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                content += thirdIndent + '<title territory="'+dictionary['territories'][0]+'">'+dictionary['event']+'</title>\n'
            else:
                content += thirdIndent + '<title>'+dictionary['event']+'</title>\n'
            #endif            
            if dictionary.has_key('description') and dictionary['description']:
                if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                    content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                else:
                    content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                #endif
            #endif
            if dictionary.has_key('date') and dictionary['date']:
                timeTuple = time.localtime(int(dictionary['date']))
                content += thirdIndent + '<date day="'+str(timeTuple[2])+'" month="'+str(timeTuple[1])+'" year="'+str(timeTuple[0])+'"/>\n'
            #endif
            if dictionary.has_key('url') and dictionary['url']:
                content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
            #endif
            content += secondIndent + '</event>\n'
            content += firstIndent + '</events>\n'
        #endif
        return content
    #enddef
    
    def faq_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('question') and dictionary['question']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<faqs>\n'
            content += secondIndent + '<faq>\n'
            for key in dictionary.keys():
                if key == 'question':
                    if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                        content += thirdIndent + '<question territory="'+dictionary['territories'][0]+'">'+dictionary['question']+'</question>\n'
                    else:
                        content += thirdIndent + '<question>'+dictionary['question']+'</question>\n'
                    #endif
                elif key == 'answer':
                    if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                        content += thirdIndent + '<answer territory="'+dictionary['territories'][0]+'">'+dictionary['answer']+'</answer>\n'
                    else:
                        content += thirdIndent + '<answer>'+dictionary['answer']+'</answer>\n'
                    #endif
                elif key == 'image_url':
                    content += thirdIndent + '<image url="'+dictionary['image_url']+'"'
                    if dictionary.has_key('image_caption') and dictionary['image_caption']:
                        content += ' caption="'+dictionary['image_caption']+'"'
                    #endif
                    content += ' />\n'
                elif key == 'source_code':
                    content += thirdIndent + '<sourceCode'
                    if dictionary.has_key('programming_languages') and dictionary['programming_languages']:
                        content += ' programmingLanguage="'+dictionary['programming_languages'][0]+'"'
                    #endif
                    content += '>'+dictionary['source_code']+'</sourceCode>\n'
                #endif
            #endfor
            content += secondIndent + '</faq>\n'
            content += firstIndent + '</faqs>\n'
        #endif
        return content
    #enddef
    
    def forum_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('forum') and dictionary['forum']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<forums>\n'
            content += secondIndent + '<forum>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'forum':
                        content += thirdIndent + '<name>'+dictionary['forum']+'</name>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'url':
                        content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</forum>\n'
            content += firstIndent + '</forums>\n'
        #endif
        return content
    #enddef
    
    def glossary_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('glossary_term') and dictionary['glossary_term']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<glossary>\n'
            content += secondIndent + '<entry>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'glossary_term':
                        content += thirdIndent + '<term>'+dictionary['glossary_term']+'</term>\n'
                    elif key == 'glossary_definition':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<definition territory="'+dictionary['territories'][0]+'">'+dictionary['glossary_definition']+'</definition>\n'
                        else:
                            content += thirdIndent + '<definition>'+dictionary['glossary_definition']+'</definition>\n'
                        #endif
                    elif key == 'image_url':
                        content += thirdIndent + '<image url="'+dictionary['image_url']+'"'
                        if dictionary.has_key('image_caption') and dictionary['image_caption']:
                            content += ' caption="'+dictionary['image_caption']+'"'
                        #endif
                        content += ' />\n'
                    elif key == 'source_code':
                        content += thirdIndent + '<sourceCode'
                        if dictionary.has_key('programming_languages') and dictionary['programming_languages']:
                            content += ' programmingLanguage="'+dictionary['programming_languages'][0]+'"'
                        #endif
                        content += '>'+dictionary['source_code']+'</sourceCode>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</entry>\n'
            content += firstIndent + '</glossary>\n'
        #endif
        return content
    #enddef
    
    def magazine_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('magazine') and dictionary['magazine']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<magazines>\n'
            content += secondIndent + '<magazine>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'identifier':
                        content += thirdIndent + '<issn>'+dictionary['identifier']+'</issn>\n'
                    elif key == 'magazine':
                        content += thirdIndent + '<title>'+dictionary['magazine']+'</title>\n'
                    elif key == 'pricing':
                        content += thirdIndent + '<pricing>\n'
                        content += self.pricing_as_xml(dictionary['pricing'])
                        content += thirdIndent + '</pricing>\n'
                    elif key == 'publisher':
                        content += thirdIndent + '<publisher>'+dictionary['publisher']+'</publisher>\n'
                    elif key == 'url':
                        content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                    #endif
                #endif
            #endfor
            content += secondIndent + '</magazine>\n'
            content += firstIndent + '</magazines>\n'
        #endif
        return content
    #enddef
    
    def project_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('project') and dictionary['project']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<projects>\n'
            content += secondIndent + '<project>\n'
            content += thirdIndent + '<name>'+dictionary['project']+'</name>\n'
            if dictionary.has_key('description') and dictionary['description']:
                if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                    content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                else:
                    content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                #endif
            #endif
            if dictionary.has_key('url') and dictionary['url']:
                content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
            #endif
            content += secondIndent + '</project>\n'
            content += firstIndent + '</projects>\n'
        #endif
        return content
    #enddef
    
    def standalone_relocatable_module_as_xml(self, document):
        content = ""
        firstIndent = ""
        secondIndent = ""
        thirdIndent = ""
        fourthIndent = ""
        for indentCount in range(4):
            firstIndent += '&nbsp;'
            secondIndent += '&nbsp;&nbsp;'
            thirdIndent += '&nbsp;&nbsp;&nbsp;'
            fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
        #endfor
        content += firstIndent + '<relocatableModules>\n'
        for dictionary in document['relocatable_modules']:
            content += secondIndent + '<relocatableModule>\n'
            for key in dictionary.keys():
                if key == 'addressing_mode':
                    if dictionary['addressing_mode'] in ['26-bit','32-bit','26/32-bit']:
                        content += thirdIndent + '<addressingMode>'+dictionary['addressing_mode']+'</addressingMode>\n'
                    #endif
                elif key == 'name':
                    content += thirdIndent + '<name>'+dictionary['name']+'</name>\n'
                elif key == 'software_interrupts':
                    content += thirdIndent + '<softwareInterrupts>\n'
                    content += self.software_interrupts_as_xml(dictionary['software_interrupts'])
                    content += thirdIndent + '</softwareInterrupts>\n'
                elif key == 'star_commands':
                    content += thirdIndent + '<starCommands>\n'
                    content += self.star_commands_as_xml(dictionary['star_commands'])
                    content += thirdIndent + '</starCommands>\n'
                elif key == 'url':
                    content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                elif key == 'version':
                    content += thirdIndent + '<version>'+dictionary['version']+'</version>\n'
                #endif
            #endfor
            content += secondIndent + '</relocatableModule>\n'
        #endfor
        content += firstIndent + '</relocatableModules>\n'
        return content
    #enddef
    
    def standalone_absolute_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('absolutes') and dictionary['absolutes']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<absolutes>\n'
            for absolute in dictionary['absolutes']:
                content += secondIndent + '<absolute>\n'
                content += thirdIndent + '<name>'+absolute+'</name>\n'
                for key in dictionary.keys():
                    if dictionary[key]:
                        if key == 'url':
                            content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'     
                        #endif
                    #endif
                #endfor
                content += secondIndent + '</absolute>\n'
            #endfor
            content += firstIndent + '</absolutes>\n'
        #endif
        return content
    #enddef
    
    def service_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('provider') and dictionary['provider']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<services>\n'
            content += secondIndent + '<service>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'advert_url':
                        content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'pricing':
                        content += thirdIndent + '<pricing>\n'
                        content += self.pricing_as_xml(dictionary['pricing'])
                        content += thirdIndent + '</pricing>\n'
                    elif key == 'provider':
                        content += thirdIndent + '<name>'+dictionary['provider']+'</name>\n'
                    elif key in ['address','category','email','telephone','url']:
                        content += thirdIndent + '<'+key+'>'+dictionary[key]+'</'+key+'>\n'          
                    #endif
                #endif
            #endfor
            content += secondIndent + '</service>\n'
            content += firstIndent + '</services>\n'
        #endif
        return content
    #enddef
    
    def usergroup_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('user_group') and dictionary['user_group']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            fourthIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
                fourthIndent += '&nbsp;&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<userGroups>\n'
            content += secondIndent + '<userGroup>\n'
            content += thirdIndent + '<name>'+dictionary['user_group']+'</name>\n'
            if dictionary.has_key('address') and dictionary['address']:
                content += thirdIndent + '<address>'+dictionary['address']+'</address>\n'
            #endif
            if dictionary.has_key('advert_url') and dictionary['advert_url']:
                content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
            #endif
            if dictionary.has_key('contact') and dictionary['contact']:
                content += thirdIndent + '<contact>'+dictionary['contact']+'</contact>\n'
            #endif
            if dictionary.has_key('description') and dictionary['description']:
                if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                    content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                else:
                    content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                #endif
            #endif
            if dictionary.has_key('email') and dictionary['email']:
                content += thirdIndent + '<email>'+dictionary['email']+'</email>\n'
            #endif
            if dictionary.has_key('pricing') and dictionary['pricing']:
                content += thirdIndent + '<pricing>\n'
                content += self.pricing_as_xml(dictionary['pricing'])
                content += thirdIndent + '</pricing>\n'
            #endif
            if dictionary.has_key('telephone') and dictionary['telephone']:
                content += thirdIndent + '<telephone>'+dictionary['telephone']+'</telephone>\n'
            #endif
            if dictionary.has_key('url') and dictionary['url']:
                content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
            #endif
            content += secondIndent + '</userGroup>\n'
            content += firstIndent + '</userGroups>\n'
        #endif
        return content
    #enddef

    def standalone_utility_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('utilities') and dictionary['utilities']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<utilities>\n'
            for utility in dictionary['utilities']:
                content += secondIndent + '<utility>\n'
                for key in utility.keys():
                    if utility[key]:
                        if key == 'name':
                            content += thirdIndent + '<name>'+utility['name']+'</name>\n'
                        elif key == 'syntax':
                            content += thirdIndent + '<syntax>'+utility['syntax']+'</syntax>\n'
                        elif key == 'url':
                            content += thirdIndent + '<url>'+utility['url']+'</url>\n'
                        elif key == 'version':
                            content += thirdIndent + '<version>'+utility['version']+'</version>\n'                            
                        #endif
                    #endif
                #endfor
                content += secondIndent + '</utility>\n'
            #endfor
            content += firstIndent + '</utilities>\n'
        #endif
        return content
    #enddef
    
    def standalone_font_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('fonts') and dictionary['fonts']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<fonts>\n'
            for font in dictionary['fonts']:
                content += secondIndent + '<font>\n'
                content += thirdIndent + '<name>'+font+'</name>\n'
                for key in dictionary.keys():
                    if dictionary[key]:
                        if key == 'url':
                            content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                        elif key == 'image_url':
                            content += thirdIndent + '<image url="'+dictionary['image_url']+'"'
                            if dictionary.has_key('image_caption') and dictionary['image_caption']:
                                content += ' caption="'+dictionary['image_caption']+'"'
                            #endif
                            content += ' />\n'
                        #endif
                    #endif
                #endfor
                content += secondIndent + '</font>\n'
            #endfor
            content += firstIndent + '</fonts>\n'
        #endif
        return content
    #enddef 
    
    def monitor_definition_file_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('monitor_definition_files') and dictionary['monitor_definition_files']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<monitorDefinitionFiles>\n'
            for monitorDefinitionFile in dictionary['monitor_definition_files']:
                content += secondIndent + '<monitorDefinitionFile>\n'
                content += thirdIndent + '<monitor>'+monitor_definition_file+'</monitor>\n'
                for key in dictionary.keys():
                    if dictionary[key]:
                        if key == 'url':
                            content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                        #endif
                    #endif
                #endfor
                content += secondIndent + '</monitorDefinitionFile>\n'
            #endfor
            content += firstIndent + '</monitorDefinitionFiles>\n'
        #endif
        return content
    #enddef     
    
    def printer_definition_file_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('printer_definition_files') and dictionary['printer_definition_files']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<printerDefinitionFiles>\n'
            for printerDefinitionFile in dictionary['printer_definition_files']:
                content += secondIndent + '<printerDefinitionFile>\n'
                content += thirdIndent + '<printer>'+printerDefinitionFile+'</printer>\n'
                for key in dictionary.keys():
                    if dictionary[key]:
                        if key == 'url':
                            content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                        #endif
                    #endif
                #endfor
                content += secondIndent + '</printerDefinitionFile>\n'
            #endfor
            content += firstIndent + '</printerDefinitionFiles>\n'
        #endif
        return content
    #enddef 
    
    def video_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('video') and dictionary['video']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<videos>\n'
            content += secondIndent + '<video>\n'
            for key in dictionary.keys():
                if dictionary[key]:
                    if key == 'height':
                        content += thirdIndent + '<height>'+dictionary['height']+'</height>\n'
                    elif key == 'description':
                        if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                            content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                        else:
                            content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                        #endif
                    elif key == 'video':
                        content += thirdIndent + '<title>'+dictionary['video']+'</title>\n'    
                    elif key == 'url':
                        content += thirdIndent + '<url>'+dictionary['url']+'</url>\n'
                    elif key == 'width':
                        content += thirdIndent + '<width>'+dictionary['width']+'</width>\n' 
                    #endif
                #endif
            #endfor
            content += secondIndent + '</video>\n'
            content += firstIndent + '</videos>\n'
        #endif
        return content
    #enddef    
    
    def developer_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('developer') and dictionary['developer']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<developers>\n'
            content += secondIndent + '<developer>\n'
            for key in dictionary.keys():
                if key == 'advert_url':
                    content += thirdIndent + '<advertUrl>'+dictionary['advert_url']+'</advertUrl>\n'
                elif key == 'description':
                    if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                        content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                    else:
                        content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                    #endif
                elif key in ['address','contact','email','telephone','url']:
                    content += thirdIndent + '<'+key+'>'+dictionary[key]+'</'+key+'>\n'
                elif key == 'developer':
                    content += thirdIndent + '<name>'+dictionary['developer']+'</name>\n'
                #endif
            #endfor
            content += secondIndent + '</developer>\n'
            content += firstIndent + '</developers>\n'
        #endif
        return content
    #enddef
    
    def howto_as_xml(self, dictionary):
        content = ""
        if dictionary.has_key('howto') and dictionary['howto']:
            firstIndent = ""
            secondIndent = ""
            thirdIndent = ""
            for indentCount in range(4):
                firstIndent += '&nbsp;'
                secondIndent += '&nbsp;&nbsp;'
                thirdIndent += '&nbsp;&nbsp;&nbsp;'
            #endfor
            content += firstIndent + '<howTos>\n'
            content += secondIndent + '<howTo>\n'
            if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                content += thirdIndent + '<task territory="'+dictionary['territories'][0]+'">'+dictionary['howto']+'</task>\n'
            else:
                content += thirdIndent + '<task>'+dictionary['howto']+'</task>\n'
            #endif
            if dictionary.has_key('description') and dictionary['description']:
                if dictionary.has_key('territories') and dictionary['territories'] and len(dictionary['territories']) == 1:
                    content += thirdIndent + '<description territory="'+dictionary['territories'][0]+'">'+dictionary['description']+'</description>\n'
                else:
                    content += thirdIndent + '<description>'+dictionary['description']+'</description>\n'
                #endif
            #endif
            if dictionary.has_key('image_url') and dictionary['image_url']:
                content += thirdIndent + '<image url="'+dictionary['image_url']+'"'
                if dictionary.has_key('image_caption') and dictionary['image_caption']:
                    content += ' caption="'+dictionary['image_caption']+'"'
                #endif
                content += ' />\n'
            #endif
            if dictionary.has_key('source_code') and dictionary['source_code']:
                content += thirdIndent + '<sourceCode'
                if dictionary.has_key('programming_languages') and dictionary['programming_languages']:
                    content += ' programmingLanguage="'+dictionary['programming_languages'][0]+'"'
                #endif
                content += '>'+dictionary['source_code']+'</sourceCode>\n'
            #endif
            content += secondIndent + '</howTo>\n'
            content += firstIndent + '</howTos>\n'
        #endif
        return content
    #enddef
    
    @cherrypy.expose
    def report_abuse(self, doc_id=""):
        if doc_id:
            content = ""
            status = self.cookie_handling()
            content += self.header(status, 'index, nofollow')
            content += '<h2>Thank You For Reporting Abuse!</h2>'
            content += '<div id="introduction">'
            if self.riscosCollection.find({'_id':ObjectId(doc_id)}).count():
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    toBeQuarantined = False
                    if document.has_key('url') and document['url']:
                        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(document['url'])
                        if self.blacklisted_domains.has_key(netloc):
                            toBeQuarantined = True
                        #endif
                        if not self.trusted_domains.has_key(netloc):
                            toBeQuarantined = True
                        #endif
                        if toBeQuarantined:
                            self.quarantineCollection.insert(document)
                            self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                            content += '<h3>The individual record you clicked upon has now been quarantined!</h3>'
                        #endif
                    else:
                        self.quarantineCollection.insert(document)
                        self.riscosCollection.remove({'_id':ObjectId(document['_id'])})
                        content += '<h3>The individual record you clicked on has now been quarantined!</h3>'                        
                    #endif
                #endif
            #endif
            content += '</div>'
            content += self.footer()
            return content
        else:
            raise cherrypy.HTTPRedirect("/riscos/index", 302)
        #endif
    #enddef
    
    @cherrypy.expose
    def switch_mirror(self, mirror):
        raise cherrypy.HTTPRedirect('http://'+mirror, 302)
    #enddef
    
    @cherrypy.expose
    def remove_from_watchlist(self, doc_id, origin, nested=False):
        status = self.cookie_handling()
        if doc_id:
            userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
            if userDocument.has_key('watchlist') and doc_id in userDocument['watchlist']:
                items = userDocument['watchlist']
                watchlistItems = []
                for item in items:
                    if item != doc_id:
                        watchlistItems.append(item)
                    #endif
                #endfor
                userDocument['watchlist'] = watchlistItems
                self.usersCollection.save(userDocument)
            #endif
        #endif
        if origin == 'advanced_search':
            if nested:
                raise cherrypy.HTTPRedirect("/riscos/advanced_search?nested=true", 302)
            else:
                raise cherrypy.HTTPRedirect("/riscos/advanced_search", 302)
            #endif
        else:
            raise cherrypy.HTTPRedirect("/riscos/"+origin, 302)
        #endif
    #enddef
       
    @cherrypy.expose
    def logon(self, mode="", username="", firstname="", surname="", password="", passwordconfirm=""):
        status = self.cookie_handling()
        guestDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content = ""
        content += self.header(status, 'noindex, follow')
        content += '<div id="introduction">'
        logonFailureMessage = ""
        registrationFailureMessage = ""
        
        if not mode or mode=="logon":
            if username and password:
                memberDocument = self.usersCollection.find_one({"username":username,"password":password})
                if memberDocument:
                    guestDocument['member'] = username
                    self.usersCollection.save(guestDocument)
                    raise cherrypy.HTTPRedirect("/riscos/index", 302)
                else:
                    logonFailureMessage = '<p class="warning">Username and/or password incorrect!</p>'
                    username = ""
                    password = ""
                #endif
            #endif
        elif mode=="register":
            if username:
                memberDocument = self.usersCollection.find_one({"username":username})
                if memberDocument:
                    registrationFailureMessage = '<p class="warning">Sorry, that username already exists!</p>'
                else:
                    if password and passwordconfirm:
                        if password == passwordconfirm:
                            memberDocument = {}
                            memberDocument['username'] = username
                            memberDocument['password'] = password
                            if firstname:
                                memberDocument['firstname'] = firstname
                            #endif
                            if surname:
                                memberDocument['surname'] = surname
                            #endif
                            self.usersCollection.insert(memberDocument)
                            guestDocument['member'] = username
                            self.usersCollection.save(guestDocument)
                        #endif
                    #endif
                #endif
            #endif
        #endif
        
        if not username or not password:
            content += '<table border="0"><tr><td><h2>Logon</h2></td><td><h2>Registration</h2></td></tr>'
            content += '<tr><td><p class="introduction">If you\'re already a registered member, you may logon here by entering your username and password</p></td><td><p class="introduction">You may register as a member by completing the form below. The primary benefits of becoming a member are that you\'ll be able to submit URLs to us and your filter settings will be remembered from one visit to the next.</p></td></tr>'
            content += '<tr><td>'
            content += '<form action="/riscos/logon" method="post"><input type="hidden" name="mode" value="logon"><table width="100%" border="0">'
            if logonFailureMessage:
                content += '<tr><td colspan="2">'+logonFailureMessage+'</td></tr>'
            #endif
            content += '<tr><td>Username (Email Address)</td><td><input type="text" size="40" name="username"></td></tr><tr><td align="right">Password</td><td><input type="password" size="40" name="password"></td></tr><tr><td colspan="2"><input class="button" type="submit" value="Logon"></td></tr></table></form>'
            content += '</td><td>'
            content += '<form action="/riscos/logon" method="post"><input type="hidden" name="mode" value="register"><table border="0">'
            if registrationFailureMessage:
                content += '<tr><td colspan="2">'+registrationFailureMessage+'</td></tr>'
            #endif
            content += '<tr><td>Username (Email Address)</td><td><input type="text" size="40" name="username"></td></tr>'
            content += '<tr><td align="right">First Name</td><td><input type="text" size="40" name="firstname"></td></tr><tr><td align="right">Surname</td><td><input type="text" size="40" name="surname"></td></tr>'
            content += '<tr><td align="right">Password</td><td><input type="password" size="40" name="password"></td></tr><tr><td align="right">Confirm Password</td><td><input type="password" size="40" name="passwordconfirm"></td></tr>'
            content += '<tr><td colspan="2"><input class="button" type="submit" value="Register"></td></tr></table></form>'
            content += '</td></tr></table>'
        #endif
        content += '</div>'
        content += self.footer()
        return content
    #enddef

    @cherrypy.expose
    def view_watchlist(self, nested=False):
        status = self.cookie_handling()
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument.has_key('watchlist') and userDocument['watchlist']:
            content = ""
            content += self.header(status, 'noindex, follow')
            if userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(userDocument['watchlist'], 'view_watchlist', nested)
            else:
                content += self.display_document_report(userDocument['watchlist'], 'view_watchlist', nested)
            #endif
            content += '</div></body>'
            content += self.footer()
            return content
        else:
            if nested:
                raise cherrypy.HTTPRedirect("/riscos/advanced_search?nested=true", 302)
            else:
                raise cherrypy.HTTPRedirect("/riscos/generic_search", 302)
            #endif
        #endif
    #enddef
    
    @cherrypy.expose
    def clear_watchlist(self, nested=False):
        status = self.cookie_handling()
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument.has_key('watchlist') and userDocument['watchlist']:
            userDocument['watchlist'] = []
            self.usersCollection.save(userDocument)
        #endif
        if nested:
            raise cherrypy.HTTPRedirect("/riscos/advanced_search?nested=true", 302)
        else:
            raise cherrypy.HTTPRedirect("/riscos/generic_search", 302)
        #endif
    #enddef
       
    def get_filter_settings(self, userDocument):
        memberDocument = ""
        if userDocument:
            if userDocument.has_key('member') and userDocument['member']:
                memberDocument = self.usersCollection.find_one({"username":userDocument['member']})
            #endif
        #endif
        
        if memberDocument and memberDocument.has_key('riscos_version') and memberDocument['riscos_version']:
            selectedRiscosVersion = memberDocument['riscos_version']
        elif userDocument and userDocument.has_key('riscos_version') and userDocument['riscos_version']:
            selectedRiscosVersion = userDocument['riscos_version']
        else:
            selectedRiscosVersion = "5.00"
        #endif
     
        if memberDocument and memberDocument.has_key('addressing_mode') and memberDocument['addressing_mode']:
            selectedAddressingMode = memberDocument['addressing_mode']
        elif userDocument and userDocument.has_key('addressing_mode') and userDocument['addressing_mode']:
            selectedAddressingMode = userDocument['addressing_mode']
        else:
            selectedAddressingMode = "32-bit"
        #endif
   
        if memberDocument and memberDocument.has_key('arm_architecture') and memberDocument['arm_architecture']:
            selectedArmArchitecture = memberDocument['arm_architecture']
        elif userDocument and userDocument.has_key('arm_architecture') and userDocument['arm_architecture']:
            selectedArmArchitecture = userDocument['arm_architecture']
        else:
            selectedArmArchitecture = "ARMv5"
        #endif
        
        if memberDocument and memberDocument.has_key('territory') and memberDocument['territory']:
            selectedTerritory = memberDocument['territory']
        elif userDocument and userDocument.has_key('territory') and userDocument['territory']:
            selectedTerritory = userDocument['territory']
        else:
            selectedTerritory = "English"
        #endif
        
        if memberDocument and memberDocument.has_key('start_year') and memberDocument['start_year']:
            selectedStartYear = memberDocument['start_year']
        elif userDocument and userDocument.has_key('start_year') and userDocument['start_year']:
            selectedStartYear = userDocument['start_year']
        else:
            selectedStartYear = "2002"
        #endif
        
        if memberDocument and memberDocument.has_key('end_year') and memberDocument['end_year']:
            selectedEndYear = memberDocument['end_year']
        elif userDocument and userDocument.has_key('end_year') and userDocument['end_year']:
            selectedEndYear = userDocument['end_year']
        else:
            selectedEndYear = str(time.localtime()[0])
        #endif

        if memberDocument and memberDocument.has_key('view') and memberDocument['view']:
            selectedView = memberDocument['view']
        elif userDocument and userDocument.has_key('view') and userDocument['view']:
            selectedView = userDocument['view']
        else:
            selectedView = 'table'
        #endif
       
        if memberDocument and memberDocument.has_key('web_sites') and memberDocument['web_sites']:
            selectedWebsites = memberDocument['web_sites']
        elif userDocument and userDocument.has_key('web_sites') and userDocument['web_sites']:
            selectedWebsites = userDocument['web_sites']
        else:
            selectedWebsites = 'disabled'
        #endif
        
        return selectedRiscosVersion, selectedAddressingMode, selectedArmArchitecture, selectedTerritory, selectedStartYear, selectedEndYear, selectedView, selectedWebsites     
    #enddef
    
    def header(self, status, robotsContent=""):
        nested = False
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        selectedRiscosVersion, selectedAddressingMode, selectedArmArchitecture, selectedTerritory, selectedStartYear, selectedEndYear, selectedView, selectedWebsites = self.get_filter_settings(userDocument)
        content = '<!DOCTYPE html>'
        content += '<html><head>'
        content += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
        content += '<title>RISC OS Search Engine @ '+self.mirror+'</title>'
        content += '<meta name="description" content="A completely automated search engine for absolute files, applications, filetypes, fonts, relocatable modules, monitor definition files, printer definition files and utilities compatible with the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers">'
        content += '<meta name="author" content="Rebecca Shalfield">'
        if userDocument:
            if not userDocument["ip_address"].startswith('192.168'):
                cherrypy.response.headers['Location'] = "http://www.shalfield.com"
            #endif
            if userDocument and userDocument.has_key('nested'):
                nested = userDocument['nested']
            #endif
        #endif
        if robotsContent:
            content += '<meta name="robots" content="'+robotsContent+'">'
        #endif
        content += '<link rel="stylesheet" type="text/css" href="/riscos/riscos.css">'
        content += '<link rel="stylesheet" href="/riscos/jquery-ui-1.8.21.custom/css/custom-theme/jquery-ui-1.8.21.custom.css">'
        content += '<script type="text/javascript" src="/riscos/jquery-ui-1.8.21.custom/js/jquery-1.7.2.min.js"></script>'
        content += '<script type="text/javascript" src="/riscos/jquery-ui-1.8.21.custom/js/jquery-ui-1.8.21.custom.min.js"></script>'
        content += '<script type="text/javascript" src="/riscos/jquery-ui-1.8.21.custom/development-bundle/ui/jquery.ui.core.js"></script>'
        content += '<script type="text/javascript" src="/riscos/riscos.js"></script>'
        content += '<link href="/riscos/atomfeed" type="application/atom+xml" rel="alternate" title="The RISC OS Search Engine ATOM Feed">'
        content += '</head>'
        content += '<body>'
        content += '<table id="header">'
        content += '<tr><th id="topbar" colspan="2" align="right"><a href="mail:rebecca.shalfield@shalfield.com">Contact Us</a> |   Mirror: <form class="inline" action="/riscos/switch_mirror" method="post"><select name="mirror" title="Select mirror">'
        for mirror in self.mirrors:
            if mirror == self.mirror:
                content += '<option value="'+mirror+'" selected>'+mirror+'</option>'
            else:
                content += '<option value="'+mirror+'">'+mirror+'</option>'
            #endif
        #endfor
        content += '</select><input class="button" type="submit" value="Switch"></form> | '
        if userDocument:
            if userDocument.has_key('member') and userDocument['member']:
                memberDocument = self.usersCollection.find_one({"username":userDocument['member']})
                if memberDocument.has_key('firstname') and memberDocument['firstname']:
                    content += "Welcome "+memberDocument['firstname']+"!"
                else:
                    content += "Welcome!"
                #endif
            else:
                content += '<form class="inline" action="/riscos/logon" method="post"><input class="button" type="submit" value="Logon"></form>'
            #endif
        else:
            content += '<form class="inline" action="/riscos/logon" method="post"><input class="button" type="submit" value="Logon"></form>'
        #endif
        content += '</th></tr>'
        content += '<tr><th id="logo" rowspan="5"><a href="/riscos/index" target="_top"><img src="/riscos/images/cogwheel.gif" alt="Cogwheel"></a></th></tr>'
        content += '<tr><th id="titlebar"><b class="inline" id="title"><sup>The</sup> RISC OS Search Engine</b></th></tr>'
        content += '<tr><th id="upperbuttonbar"><form class="inline" action="/riscos/absolute" method="post"><input class="button" type="submit" value="Absolutes" title="Search for Absolutes"></form> <form class="inline" action="/riscos/app" method="post"><input class="button" type="submit" value="Apps" title="Search for Applications"></form> <form class="inline" action="/riscos/book" method="post"><input class="button" type="submit" value="Books" title="Search for Books"></form> <form class="inline" action="/riscos/computer" method="post"><input class="button" type="submit" value="Computers" title="Search for Computers"></form> <form class="inline" action="/riscos/dealer" method="post"><input class="button" type="submit" value="Dealers" title="Search for Dealers"></form> <form class="inline" action="/riscos/developer" method="post"><input class="button" type="submit" value="Developers" title="Search for Developers"></form> <form class="inline" action="/riscos/errormessage" method="post"><input class="button" type="submit" value="Error Messages" title="Search for Error Messages"></form> <form class="inline" action="/riscos/event" method="post"><input class="button" type="submit" value="Events" title="Search for Events"></form> <form class="inline" action="/riscos/faq" method="post"><input class="button" type="submit" value="FAQs" title="Search for Frequently Asked Questions"></form> <form class="inline" action="/riscos/filetype" method="post"><input class="button" type="submit" value="Filetypes" title="Search for Filetypes"></form> <form class="inline" action="/riscos/font" method="post"><input class="button" type="submit" value="Fonts" title="Search for Fonts"></form> <form class="inline" action="/riscos/forum" method="post"><input class="button" type="submit" value="Forums" title="Search for Forums"></form> <form class="inline" action="/riscos/glossary" method="post"><input class="button" type="submit" value="Glossary" title="Search for Glossary Terms"></form> <form class="inline" action="/riscos/howto" method="post"><input class="button" type="submit" value="How-Tos" title="Search for How-Tos"></form> <form class="inline" action="/riscos/magazine" method="post"><input class="button" type="submit" value="Magazines" title="Search for Magazines"></form> <form class="inline" action="/riscos/module" method="post"><input class="button" type="submit" value="Modules" title="Search for Relocatable Modules"></form> <form class="inline" action="/riscos/monitor" method="post"><input class="button" type="submit" value="Monitor DFs" title="Search for Monitor Definition Files"></form> <form class="inline" action="/riscos/peripheral" method="post"><input class="button" type="submit" value="Peripherals" title="Search for Peripherals"></form> <form class="inline" action="/riscos/podule" method="post"><input class="button" type="submit" value="Podules" title="Search for Podules"></form> <form class="inline" action="/riscos/printer" method="post"><input class="button" type="submit" value="Printer DFs" title="Search for Printer Definition Files"></form> <form class="inline" action="/riscos/project" method="post"><input class="button" type="submit" value="Projects" title="Search for Projects"></form> <form class="inline" action="/riscos/service" method="post"><input class="button" type="submit" value="Services" title="Search for Services"></form> <form class="inline" action="/riscos/softwareinterrupt" method="post"><input class="button" type="submit" value="SWIs" title="Search for SoftWare Interrupts (SWIs)"></form> <form class="inline" action="/riscos/starcommand" method="post"><input class="button" type="submit" value="* Commands" title="Search for * (Star) Commands"></form> <form class="inline" action="/riscos/usergroup" method="post"><input class="button" type="submit" value="User Groups" title="Search for User Groups"></form> <form class="inline" action="/riscos/utility" method="post"><input class="button" type="submit" value="Utilities" title="Search for Utilities"></form> <form class="inline" action="/riscos/video" method="post"><input class="button" type="submit" value="Videos" title="Search for Videos"></form></th></tr>'
        content += '<tr><td class="filter"><form class="inline" action="/riscos/filter" method="post">'
        content += '<table class="filter"><tr><td>RISC OS Version</td><td>Addressing Mode</td><td>ARM Architecture</td><td>Territory</td><td>Start Year</td><td>End Year</td><td>View</td><td>Embed Web Sites</td></tr>'       
        content += '<tr><td><select name="riscosversion" title="Select your version of RISC OS noting that 5.xx is in one fork and 4.xx/6.xx in the other">'
        selectedRiscosVersion, selectedAddressingMode, selectedArmArchitecture, selectedTerritory, selectedStartYear, selectedEndYear, selectedView, selectedWebsites = self.get_filter_settings(userDocument)
        for (textualRiscosVersion,riscOsVersion) in self.riscOsVersions:
            if selectedRiscosVersion and riscOsVersion == selectedRiscosVersion:
                content += '<option value="'+riscOsVersion+'" selected>'+textualRiscosVersion+'</option>'
            else:
                content += '<option value="'+riscOsVersion+'">'+textualRiscosVersion+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="addressingmode" title="Select the addressing mode, 26-bit (older) or 32-bit (newer), used by RISC OS">'
        for addressingMode in ['26-bit','32-bit','26/32-bit']:
            if addressingMode == selectedAddressingMode:
                content += '<option value="'+addressingMode+'" selected>'+addressingMode+'</option>'
            else:
                content += '<option value="'+addressingMode+'">'+addressingMode+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="armarchitecture" title="Select the ARM architecture applicable for your computer">'
        for (armArchitecture,modelsCovered) in self.armArchitectures:
            if armArchitecture == selectedArmArchitecture:
                content += '<option value="'+armArchitecture+'" title="'+modelsCovered+'" selected>'+armArchitecture+'</option>'
            else:
                content += '<option value="'+armArchitecture+'" title="'+modelsCovered+'">'+armArchitecture+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="territory" title="Select the territory you wish to find software for">'       
        for territory in self.territories:
            if territory == selectedTerritory:
                content += '<option value="'+territory+'" selected>'+territory+'</option>'
            else:
                content += '<option value="'+territory+'">'+territory+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="startyear">'
        for startYear in range(1987,time.localtime()[0]+2):
            if startYear == int(selectedStartYear):
                content += '<option value="'+str(startYear)+'" selected>'+str(startYear)+'</option>'
            else:
                content += '<option value="'+str(startYear)+'">'+str(startYear)+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="endyear">'
        for endYear in range(1987,time.localtime()[0]+2):
            if endYear == int(selectedEndYear):
                content += '<option value="'+str(endYear)+'" selected>'+str(endYear)+'</option>'
            else:
                content += '<option value="'+str(endYear)+'">'+str(endYear)+'</option>'
            #endif
        #endfor        
        content += '</select></td><td><select name="view">'
        for view in ['table','report']:
            if view == selectedView:
                content += '<option value="'+view+'" selected>'+view.capitalize()+'</option>'
            else:
                content += '<option value="'+view+'">'+view.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="websites" title="Enable to embed relevant RISC OS-related web sites within any search results">'
        for websites in ['disabled','enabled 640x480','enabled 800x600','enabled 1024x768']:
            if websites == selectedWebsites:
                content += '<option value="'+websites+'" selected>'+websites.capitalize()+'</option>'
            else:
                content += '<option value="'+websites+'">'+websites.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select></td><td><input type="hidden" name="origin" value="index"><input class="button" type="submit" value="Filter"></td></tr></table></form>'
        content += '</td></tr>'
        content += '<tr><th id="lowerbuttonbar"><form class="inline" action="/riscos/introduction" method="post"><input class="button" type="submit" value="Introduction"></form> <form class="inline" action="/riscos/news" method="post"><input class="button" type="submit" value="News"></form> <form class="inline" action="/riscos/categorisation"><input class="button" type="submit" value="Categorisation"></form> <form class="inline" action="/riscos/generic_search" method="post"><input class="button" type="submit" value="Generic Search" title="Allows you to enter a single search as either a string or a regular expression"></form> <form class="inline" action="/riscos/advanced_search" method="post"><input class="button" type="submit" value="Advanced Search" title="Allows you to enter multiple searches as regular expressions"></form> <form class="inline" action="/riscos/filetypenavigator" method="post"><input class="button" type="submit" value="Filetype Navigator" title="Allows you to navigate from one application to the next via the filetypes it supports"></form> <form class="inline" action="/riscos/websites" method="post"><input class="button" type="submit" value="Web Sites"></form> <form class="inline" action="/riscos/ftpsites" method="post"><input class="button" type="submit" value="FTP Sites"></form> <form class="inline" action="/riscos/randomrecord" method="post"><input class="button" type="submit" value="Random Record" title="Displays a record at random"></form> <form class="inline" action="/riscos/randomapp" method="post"><input class="button" type="submit" value="Random App" title="Displays details of a RISC OS application at random"></form> <form class="inline" action="/riscos/randomurl" method="post"><input class="button" type="submit" value="Random URL" title="Takes you to a URL at random directly related to a RISC OS application"></form> <form class="inline" action="/riscos/randomvideo" method="post"><input class="button" type="submit" value="Random Video" title="Takes you to a RISC OS-related video at random"></form>'
        if userDocument and userDocument.has_key('watchlist') and userDocument['watchlist']:
            content += ' | <form class="inline" action="/riscos/view_watchlist" method="post">'
            if nested:
                content += '<input type="hidden" name="nested" value="true">'
            #endif
            content += '<input class="button" class="watchlist" type="submit" value="View" title="Display contents of watchlist"></form> <form class="inline" action="/riscos/clear_watchlist" method="post">'
            if nested:
                content += '<input type="hidden" name="nested" value="true">'
            #endif            
            content += '<input class="button" class="watchlist" type="submit" value="Clear" title="Empty watchlist"></form>'
        #endif
        content += '</th></tr>'
        content += '</table>'
        content += '<div class="maincontent">'
        if status == "new":
            content += '<h3 class="warning">We use cookies to ensure that we give you the best experience on our website<br>If you continue without changing your settings, we\'ll assume that you are happy to receive all cookies from this website</h3>'
            content += '<h3 class="warning">You are visiting from '+cherrypy.request.remote.ip+' ['+cherrypy.request.headers['User-Agent']+']</h3>'       
        #endif
        return content     
    #enddef
    
    @cherrypy.expose
    def websites(self):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Web Sites</h2>'
        content += '<div id="introduction">'
        websites = []
        domains = self.riscosCollection.find({"url":{"$exists":True,"$ne":""},"page_title":{"$exists":True,"$ne":""},"domain":{"$exists":True,"$ne":""}}).distinct('domain')
        for domain in domains:
            shortestUrl = ""
            for document in self.riscosCollection.find({"url":{"$exists":True,"$ne":""},"page_title":{"$exists":True,"$ne":""},"domain":domain}):
                if shortestUrl == "" or len(document['url']) < len(shortestUrl):
                    shortestUrl = document['url']
                #endif
            #endfor
            if shortestUrl:
                selectedDocument = self.riscosCollection.find_one({"url":shortestUrl,"page_title":{"$exists":True,"$ne":""},"domain":domain})
                if selectedDocument:
                    websites.append((selectedDocument['page_title'].lower().strip(),selectedDocument['page_title'].strip(),selectedDocument['url']))
                #endif
            #endif
        #endfor
        if websites:
            websites.sort()
            content += '<ul>'
            for (lowerPageTitle,pageTitle,url) in websites:
                content += '<li><a href="'+url+'" target="_blank">'+pageTitle+'</a></li>'
            #endfor
            content += '</ul>'
        #endif
        content += '</div>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def ftpsites(self):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>FTP Sites</h2>'
        content += '<div id="introduction">'       
        searchCriteria = {}
        searchCriteria['url'] = re.compile('(?i)^ftp://')
        ftpsites = self.riscosCollection.find(searchCriteria).distinct('url')
        if ftpsites:
            ftpsites.sort()
            content += '<ul>'
            for ftpsite in ftpsites:
                content += '<li><a href="'+ftpsite+'" target="_blank">'+ftpsite+'</a></li>'
            #endfor
            content += '</ul>'
        #endif
        content += '</div>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def randomapp(self):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Random App</h2>'     
        distinctApps = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""}}).distinct("directory")
        appFound = False
        while distinctApps and not appFound:
            randomNo = randint(0,len(distinctApps)-1)
            doc_ids = self.riscosCollection.find({"directory":distinctApps[randomNo]}).distinct('_id')
            filteredDocIds = self.apply_filter(userDocument, doc_ids)
            if filteredDocIds:
                content += '<h3>'+str(randomNo+1)+' of '+str(len(distinctApps))+'</h3>'
                if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                    content += self.display_document_table(filteredDocIds, 'randomapp', False)
                else:
                    content += self.display_document_report(filteredDocIds, 'randomapp', False)
                #endif
                appFound = True  

                if len(filteredDocIds) == 1:
                    content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
                #endif
                
            #endif
        #endwhile
        content += self.footer()
        return content
    #enddef
    
    def display_dictionary_as_xml_and_json(self, docId):
        content = ""
        document = self.riscosCollection.find_one({'_id':ObjectId(docId)})
        content += '<table width="100%" border="0"><tr><td valign="top" width="50%"><div class="white">'
        content += '<h3 class="underlined">Record in riscos.xml Format</h3>'
        if document.has_key('_id'):
            del document['_id']
        #endif
        content += '<p align="left">'
        xmlCode = self.dictionary_as_xml(document)
        content += self.post_process_xml_code(xmlCode)
        content += '</p>'
        content += '</div></td><td valign="top" width="50%"><div class="white">'
        content += '<h3 class="underlined">Record in JSON Format</h3>'
        content += '<p class="json">'
        content += self.dictionary_as_json(document, 0)
        content += '</p>'
        content += '</div></td></tr></table>'
        return content        
    #enddef
    
    @cherrypy.expose
    def randomrecord(self):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Random Record</h2>'
        doc_ids = self.riscosCollection.find({'syndicated_feed':{'$exists':False},'zip_file':{'$exists':False}}).distinct("_id")
        randomNo = randint(0,len(doc_ids)-1)
        document = self.riscosCollection.find_one({'_id':ObjectId(doc_ids[randomNo])})
        if document:
            content += '<h3>'+str(randomNo+1)+' of '+str(len(doc_ids))+'</h3>'
            try:
                if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                    content += self.display_document_table([doc_ids[randomNo]], 'randomrecord', False)
                else:
                    content += self.display_document_report([doc_ids[randomNo]], 'randomrecord', False)
                #endif

                content += self.display_dictionary_as_xml_and_json(doc_ids[randomNo])
            except:
                True
        
        #endif
        
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def filetypenavigator(self, seedfiletype=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Filetype Navigator</h2>'
        
        if not seedfiletype:
            distinctFiletypesRun = self.riscosCollection.find({"filetypes_run":{"$exists":True,"$ne":[]}}).distinct("filetypes_run")
            distinctFiletypesSet = self.riscosCollection.find({"filetypes_set":{"$exists":True,"$ne":[]}}).distinct("filetypes_set")
            distinctFiletypes = distinctFiletypesRun + distinctFiletypesSet
            distinctFiletypes.sort()
            content += '<p><form action="/riscos/filetypenavigator" method="post">Filetype: <select name="seedfiletype">'
            for filetype in distinctFiletypes:
                content += '<option value="'+filetype+'">'+filetype+'</option>'
            #endfor
            content += '</select><input class="button" type="submit" value="Navigate"></form></p>'
        #endif

        if seedfiletype:
            content += '<table class="software">'
            content += '<tr><th>Application</th><th>Filetypes Run</th><th>Filetypes Set</th></tr>'
            for document in self.riscosCollection.find({"$or":[{"filetypes_run":{"$exists":True,"$ne":[]}},{"filetypes_set":{"$exists":True,"$ne":[]}}]}):
                if (document.has_key('filetypes_run') and seedfiletype in document['filetypes_run']) or (document.has_key('filetypes_set') and seedfiletype in document['filetypes_set']):
                    if (document.has_key('directory') and document['directory']) or (document.has_key('application_name') and document['application_name']):
                        content += '<tr>'
                        if document.has_key('directory') and document['directory']:
                            content += '<td>'
                            content += '<form class="inline" action="/riscos/app?search='+document['directory']+'" method="post"><input class="button" type="submit" value="'+document['directory']+'"></form>'
                            content += '</td>'
                        elif document.has_key('application_name') and document['application_name']:
                            content += '<td>'
                            content += '<form class="inline" action="/riscos/app?search='+document['application_name']+'" method="post"><input class="button" type="submit" value="'+document['application_name']+'"></form>'
                            content += '</td>'    
                        #endif
                        content += '<td>'
                        if document.has_key('filetypes_run') and document['filetypes_run']:
                            content += '<ul>'
                            for filetype in document['filetypes_run']:
                                if filetype == seedfiletype:
                                    content += '<li><b>'+filetype+'</b></li>'
                                else:
                                    content += '<li><a href="/riscos/filetypenavigator?seedfiletype='+filetype+'">'+filetype+'</a></li>'
                                #endif
                            #endfor
                            content += '</ul>'
                        #endif
                        content += '</td>'
                        content += '<td>'
                        if document.has_key('filetypes_set') and document['filetypes_set']:
                            content += '<ul>'
                            for filetype in document['filetypes_set']:
                                if filetype == seedfiletype:
                                    content += '<li><b>'+filetype+'</b></li>'
                                else:
                                    content += '<li><a href="/riscos/filetypenavigator?seedfiletype='+filetype+'">'+filetype+'</a></li>'
                                #endif
                            #endfor
                            content += '</ul>'
                        #endif                        
                        content += '</td></tr>'
                    #endif
                #endif
                
            #endfor

            content += '</table>'
        #endif
        
        content += self.footer()
        return content
    #enddef    
    
    @cherrypy.expose
    def randomvideo(self):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Random Video</h2>'       
        distinctVideos = self.riscosCollection.find({"domain":{"$in":['www.youtube.com','m.youtube.com','uk.youtube.com']},'embed':{"$exists":True}}).distinct('url')
        if distinctVideos:
            videoFound = False
            while not videoFound:
                randomNo = randint(0,len(distinctVideos)-1)
                doc_ids = self.riscosCollection.find({"url":distinctVideos[randomNo]}).distinct('_id')
                filteredDocIds = self.apply_filter(userDocument, doc_ids)
                if filteredDocIds:
                    document = self.riscosCollection.find_one({"_id":ObjectId(filteredDocIds[0])})
                    if document:
                        content += '<h3>'+str(randomNo+1)+' of '+str(len(distinctVideos))+'</h3>'
                        content += '<p>'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+self.insert_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</p>'
                        videoFound = True
                    #endif
                #endif
            #endwhile
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def randomurl(self):
        content = ""
        selectedUrl = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Random URL</h2>'   
        distinctUrls = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""},"parent_url":{"$exists":True,"$ne":""}}).distinct("parent_url")
        if distinctUrls:
            urlFound = False
            while not urlFound:
                randomNo = randint(0,len(distinctUrls)-1)
                doc_ids = self.riscosCollection.find({"parent_url":distinctUrls[randomNo]}).distinct('_id')
                filteredDocIds = self.apply_filter(userDocument, doc_ids)
                if filteredDocIds:
                    selectedUrl = distinctUrls[randomNo]
                    distinctApps = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""},"parent_url":selectedUrl}).distinct("directory")
                    content += '<h3>'+str(randomNo+1)+' of '+str(len(distinctUrls))+'</h3>'
                    urlFound = True
                #endif
            #endwhile
        #endif
        if selectedUrl:
            content += self.embed_web_site(selectedUrl, distinctApps) 
        #endif
        content += self.footer()
        return content
    #enddef
    
    def embed_web_site(self, url, distinctApps):
        content = ""
        width = 800
        height = 600 
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument and userDocument.has_key('web_sites') and userDocument['web_sites']:
            if userDocument['web_sites'] == 'enabled 640x480':
                width = 640
                height = 480        
            elif userDocument['web_sites'] == 'enabled 800x600':
                width = 800
                height = 600
            elif userDocument['web_sites'] == 'enabled 1024x768':
                width = 1024
                height = 768                
            #endif
        #endif
        content += '<table class="website"><tr><td valign="top"><iframe src="'+url+'" width="'+str(width)+'" height="'+str(height)+'"></iframe></td><td valign="top"><a class="external" href="'+url+'" target="_blank" title="'+url+'" method="post">Visit</a>'
        if distinctApps:
            distinctAppTuples = []
            for distinctApp in distinctApps:
                distinctAppTuples.append((distinctApp.lower(),distinctApp))
            #endfor
            distinctAppTuples.sort()
            content += '<hr><ul>'
            for (dummy,distinctApp) in distinctAppTuples:
                content += '<li><form class="inline" action="/riscos/app?search='+distinctApp+'" method="post"><input class="button" type="submit" value="'+distinctApp+'"></form></li>'
            #endfor
        #endif
        content += '</ul></td></tr></table><p></p>'
        return content        
    #enddef
    
    @cherrypy.expose
    def filter(self, riscosversion, addressingmode, armarchitecture, territory, startyear, endyear, view, websites, origin):
        status = self.cookie_handling()
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument:
            memberDocument = ""
            if userDocument.has_key('member') and userDocument['member']:
                memberDocument = self.usersCollection.find_one({"username":userDocument['member']})
            #endif
            if riscosversion:
                if riscosversion in ['5.00']:
                    addressingmode = '32-bit'
                elif riscosversion in ['2.00','3.00','3.10','3.11','3.20','3.50','3.60','3.70','3.71']:
                    addressingmode = '26-bit'
                #endif
            else:
                riscosversion = '5.00'
                addressingmode = '32-bit'
            #endif
            
            if riscosversion:
                if memberDocument:
                    memberDocument['riscos_version'] = riscosversion
                #endif
                userDocument['riscos_version'] = riscosversion
            #endif 
            if addressingmode:
                if memberDocument:
                    memberDocument['addressing_mode'] = addressingmode
                    print "SET " + memberDocument['addressing_mode']
                #endif
                userDocument['addressing_mode'] = addressingmode
            #endif
            if armarchitecture:
                if memberDocument:
                    memberDocument['arm_architecture'] = armarchitecture
                #endif
                userDocument['arm_architecture'] = armarchitecture
            #endif
            if territory:
                if memberDocument:
                    memberDocument['territory'] = territory
                #endif
                userDocument['territory'] = territory
            #endif
            if startyear:
                if memberDocument:
                    memberDocument['start_year'] = startyear
                #endif
                userDocument['start_year'] = startyear
            #endif
            if endyear:
                if memberDocument:
                    memberDocument['end_year'] = endyear
                #endif
                userDocument['end_year'] = endyear
            #endif
            if view:
                if memberDocument:
                    memberDocument['view'] = view
                #endif
                userDocument['view'] = view
            #endif
            if websites:
                if memberDocument:
                    memberDocument['web_sites'] = websites
                #endif
                userDocument['web_sites'] = websites
            #endif
            if memberDocument:
                self.usersCollection.save(memberDocument)
            #endif
            self.usersCollection.save(userDocument)           
        #endif
        raise cherrypy.HTTPRedirect("/riscos/"+origin, 302)
    #endddef
    
    @cherrypy.expose
    def submit_url(self, url):
        '''Allow a new URL to be added to the Database or an existing URL to be reset'''
        status = self.cookie_handling()
        if url:
            if not url.__contains__('://'):
                url = 'http://' + url
            #endif
            if not self.blacklisted_url(url):
                count = self.urlsCollection.find({'url':url}).count()
                if not count:
                    newDocument = {}
                    newDocument['url'] = url
                    if url.lower().endswith('.zip'):
                        newDocument['zip_file'] = url
                        newDocument['last_scanned'] = 0
                    elif url.lower().endswith('/riscos.xml'):
                        newDocument['riscos_xml'] = url
                        newDocument['last_scanned'] = 0
                    else:
                        if self.usual_domain(url):
                            epoch = int(time.time())
                            newDocument['last_scanned'] = randint(1,epoch-31536000)
                        else:
                            newDocument['last_scanned'] = 0
                        #endif                
                    #endif
                    self.urlsCollection.insert(newDocument)
                    print 'New URL, '+url+', added to urls'
                else:
                    print 'URL, '+url+', is already in urls!'
                    if url.lower().endswith('/riscos.xml'):
                        document = self.urlsCollection.find_one({'url':url})
                        document['riscos_xml'] = url
                        document['last_scanned'] = 0
                        self.urlsCollection.save(document)
                    #endif                        
                #endif
                if self.riscosCollection.find({'url':url}).count():
                    for existingDocument in self.riscosCollection.find({'url':url}):
                        self.riscosCollection.remove({'_id':ObjectId(existingDocument['_id'])})
                    #endfor
                #endif
            else:
                print 'Sorry, URL, '+url+', is blacklisted!'
            #endif
        else:
            print 'Missing URL'
        #endif
        raise cherrypy.HTTPRedirect("/riscos/generic_search", 302)
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
    
    def usual_domain(self, url):
        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(url)
        if netloc in self.usualDomains:
            return True
        else:
            return False
        #endif
    #enddef    
    
    @cherrypy.expose
    def remove_search_component(self, attribute, value):
        status = self.cookie_handling()
        if attribute and value:
            userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
            if userDocument:
                if userDocument.has_key('search_criteria'):
                    searchCriteria = userDocument['search_criteria']
                    if searchCriteria[attribute] == value:
                        del searchCriteria[attribute]
                        userDocument['search_criteria'] = searchCriteria
                        userDocument['key'] = attribute
                        userDocument['value'] = value
                        self.usersCollection.save(userDocument)
                        if userDocument['search_criteria'] == {}:
                            # As no search criteria, return without removal set to true to force exit from nested mode
                            raise cherrypy.HTTPRedirect("/riscos/advanced_search", 302)
                        #endif
                    #endif
                #endif
            #endif
        #endif
        raise cherrypy.HTTPRedirect("/riscos/advanced_search?removal=true", 302)
    #enddef
    
    def cookie_handling(self):
        status = ""
        try:
            cookie_string = cherrypy.request.headers['Cookie']
        except:
            cookie_string = ""
        if not cookie_string:
            self.sessionId = sha.new(repr(time.time())).hexdigest()
            self.cookie['sid'] = self.sessionId
            userDocument = {}
            userDocument["session_id"] = self.sessionId
            self.usersCollection.insert(userDocument)
            status = "new"
        else:
            self.cookie.load(cookie_string)
            self.sessionId = self.cookie['sid'].value
            status = "existing"
        #endif
        
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument:
            userDocument["ip_address"] = cherrypy.request.remote.ip
            userDocument['user_agent'] = cherrypy.request.headers['User-Agent']
            self.usersCollection.save(userDocument)
            if userDocument.has_key('member') and userDocument['member']:
                memberDocument = self.usersCollection.find_one({"username":userDocument['member']})
                if memberDocument:
                    memberDocument["ip_address"] = cherrypy.request.remote.ip
                    memberDocument['user_agent'] = cherrypy.request.headers['User-Agent']
                    self.usersCollection.save(memberDocument)
                #endif
            #endif
        #endif
        cherrypy.response.headers['Set-Cookie'] = self.cookie
        return status         
    #enddef
    
    @cherrypy.expose
    def index(self):
        content = ""
        search = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, follow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())
        
        # Delete guest documents older than 28 days
        oldGuestDocuments = self.usersCollection.find({'last_visit':{'$lt':epoch-2419200},"username":{"$exists":False}})
        for oldGuestDocument in oldGuestDocuments:
            self.usersCollection.remove({'_id':ObjectId(oldGuestDocument['_id'])})
        #endfor
        
        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
            if userDocument.has_key('value') and userDocument['value']:
                search = userDocument['value']
            #endif
        #endif
        
        content += '<table border="0" width="100%">'
        content += '<tr><td colspan="4">'
        
        content += self.insert_advert("event")

        content += '</td></tr>'
        content += '<tr><td width="25%" valign="top">'
        
        content += '<div class="partition">'
        distinctQuestions = self.riscosCollection.find({"question":{"$exists":True,"$ne":""},"answer":{"$exists":True,"$ne":""}}).distinct("question")
        questionFound = False
        while distinctQuestions and not questionFound:
            randomNo = randint(0,len(distinctQuestions)-1)
            content += '<h3 class="columnheading">Random FAQ ('+str(randomNo+1)+' of '+str(len(distinctQuestions))+')</h3>'
            content += self.display_faq_entries([distinctQuestions[randomNo]])
            questionFound = True
        #endwhile
        content += '</div>'        
        
        content += '<div class="partition">'
        distinctTerms = self.riscosCollection.find({"glossary_term":{"$exists":True,"$ne":""},"glossary_definition":{"$exists":True,"$ne":""}}).distinct("glossary_term")
        termFound = False
        while distinctTerms and not termFound:
            randomNo = randint(0,len(distinctTerms)-1)
            content += '<h3 class="columnheading">Random Glossary ('+str(randomNo+1)+' of '+str(len(distinctTerms))+')</h3>'
            content += self.display_glossary_entries([distinctTerms[randomNo]])
            termFound = True
        #endwhile
        content += '</div>'

        content += '</td><td valign="top" width="25%">'
        
        content += '<div class="partition">'
        content += '<h3 class="columnheading">News</h3>'
        
        for document in self.riscosCollection.find({'syndicated_feed':{'$exists':True},'date':{'$exists':True,'$ne':"",'$gte':epoch-self.periodMonth}}):
            if document.has_key('syndicated_feed_item_title') and document['syndicated_feed_item_title']:
                content += '<h4 align="left">'+document['syndicated_feed_item_title']+'</h4>'
            #endif
            if document.has_key('syndicated_feed_item_description') and document['syndicated_feed_item_description']:
                if document['syndicated_feed_item_description'].__contains__('</p>'):
                    content += document['syndicated_feed_item_description']
                else:
                    content += '<p align="left">'+document['syndicated_feed_item_description']+'</p>'
                #endif
            #endif
            content += '<p align="right">'
            if document.has_key('url') and document['url']:
                content += '<a href="'+document['url']+'" title="'+document['url']+'">Link</a>'
            #endif
            if document.has_key('url') and document['url'] and document.has_key('parent_url') and document['parent_url']:
                content += " | "
            #endif
            if document.has_key('parent_url') and document['parent_url']:
                content += '<a href="'+document['parent_url']+'" title="'+document['parent_url']+'">Source</a>'
            #endif
            content += '</p>'
        #endfor      
        
        content += '</div>'
        
        content += '</td><td valign="top" width="25%">'

        content += '<div class="partition">'
        content += '<h3 class="columnheading">Latest Records</h3>'
        content += self.latest_records()
        content += '</div>'
               
        content += '</td><td valign="top" width="25%">'
        
        content += '<div class="partition">'
        
        content += '<h3 class="columnheading">Search</h3>'
        
        content += '<p><form action="/riscos/generic_search" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="search" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="search" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'        
        
        content += '<h4>What Others Have Been Searching For During The Past 28 Days</h4>'
        otherUserDocuments = self.usersCollection.find({"session_id":{"$exists":True,"$ne":""},"value":{"$exists":True,"$ne":""},'last_visit':{'$gte':epoch-2419200}})
        if otherUserDocuments:
            otherSearches = []
            for otherUserDocument in otherUserDocuments:
                if otherUserDocument.has_key('format') and otherUserDocument.has_key('value') and otherUserDocument['format'] and otherUserDocument['value']:
                    otherSearches.append((otherUserDocument['value'].lower(),otherUserDocument['format'],otherUserDocument['value']))
                #endif
            #endfor
            if otherSearches:
                otherSearches = list(set(otherSearches))
                otherSearches.sort()
                content += '<p>'
                for os in range(len(otherSearches)):                   
                    content += '<a href="/riscos/generic_search?format='+otherSearches[os][1]+'&search='+otherSearches[os][2]+'">'+otherSearches[os][2]+'</a>'
                    if os < len(otherSearches)-1:
                        content += ' &bull; '
                    #endif
                #endfor
                content += '</p>'
            #endif
        #endif
        content += '</div>'
        
        members = self.usersCollection.find({'member':{"$exists":True,"$ne":""}}).distinct("member")
        if members:
            content += '<div class="partition">'
            
            content += '<h3 class="columnheading">Members</h3>'
            
            content += '<h4 align="left">The following members have recently logged on:</h4>'
            content += '<ul>'
            for member in members:
                document = self.usersCollection.find_one({'username':member})
                if document:
                    if document.has_key('firstname') and document['firstname'] and document.has_key('surname') and document['surname']:
                        content += '<li>'+document['firstname']+' '+document['surname']+'</li>'
                    elif document.has_key('firstname') and document['firstname']:
                        content += '<li>'+document['firstname']+'</li>'
                    elif document.has_key('surname') and document['surname']:
                        content += '<li>'+document['surname']+'</li>'
                    #endif
                #endif
            #endfor
            content += '</ul>'
            content += '</div>'
        #endif        
        
        content += '<div class="partition">'
        content += '<h3 class="columnheading">Links</h3>'
        content += '<ul>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn" target="_blank">comp.sys.acorn</a></li>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn.advocacy" target="_blank">comp.sys.acorn.advocacy</a></li>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn.announce" target="_blank">comp.sys.acorn.announce</a></li>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn.apps" target="_blank">comp.sys.acorn.apps</a></li>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn.hardware" target="_blank">comp.sys.acorn.hardware</a></li>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn.misc" target="_blank">comp.sys.acorn.misc</a></li>'
        content += '<li><a href="https://groups.google.com/forum/#!forum/comp.sys.acorn.programmer" target="_blank">comp.sys.acorn.programmer</a></li>'
        content += '<li><a href="http://www.drobe.co.uk/" target="_blank">Drobe</a></li>'
        content += '<li><a href="http://www.iconbar.co.uk/" target="_blank">Iconbar</a></li>'
        content += '<li><a href="http://www.myriscos.co.uk/" target="_blank">My RISC OS</a></li>'
        content += '<li><a href="http://www.raspberrypi.org/phpBB3/viewforum.php?f=55" target="_blank">Raspberry Pi RISC OS Forum</a></li>'
        content += '<li><a href="http://www.riscoscode.com/" target="_blank">RISCOScode</a></li>'
        content += '<li><a href="http://www.riscository.com/" target="_blank">Riscository</a></li>'
        content += '<li><a href="http://www.riscosopen.org/" target="_blank">RISC OS Open Ltd</a></li>'
        content += '<li><a href="http://riscpi.co.uk/" target="_blank">risc/pi</a></li>'
        content += '</ul>'
        content += '</div>'
        
        content += '</td></tr></table>'
        
        content += self.footer()
        return content
    #enddef
    
    def insert_advert(self, attribute):
        content = ""
        if attribute:
            doc_ids = self.riscosCollection.find({attribute:{'$exists':True},'url':{'$exists':True},'advert_url':{'$exists':True}}).distinct("_id")
        else:
            doc_ids = self.riscosCollection.find({'url':{'$exists':True},'advert_url':{'$exists':True}}).distinct("_id")
        #endif
        if doc_ids:
            randomNo = randint(0,len(doc_ids)-1)
            document = self.riscosCollection.find_one({'_id':ObjectId(doc_ids[randomNo])})
            content += '<p><a href="'+document['url']+'"><img border="0" src="'+document['advert_url']+'"></a></p>'
        #endif
        return content        
    #enddef
    
    def dictionary_as_xml(self, document):
        content = ""
        content += '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
        content += '<?xml-stylesheet type="text/xsl" href="http://' + self.mirror + '/riscos.xsl"?>\n'
        #content += '<riscos xmlns="http://' + self.mirror + '/namespace" version="0.99">\n'
        content += '<riscos version="0.99">\n'
        appFound = False
        for key in document.keys():
            if key == 'absolutes' and not 'application_name' in document.keys() and not 'directory' in document.keys():
                content += self.standalone_absolute_as_xml(document)
            elif key in ['directory','application_name'] and appFound == False:
                content += self.app_as_xml(document)
                appFound = True
            elif key == 'anniversary':
                content += self.anniversary_as_xml(document)
            elif key == 'book':
                content += self.book_as_xml(document)
            elif key == 'computer':
                content += self.computer_as_xml(document)
            elif key == 'dealer':
                content += self.dealer_as_xml(document)    
            elif key == 'developer' and not 'application_name' in document.keys() and not 'directory' in document.keys() and not 'computer' in document.keys() and not 'peripheral' in document.keys():
                content += self.developer_as_xml(document)
            elif key == 'error_message':
                content += self.error_message_as_xml(document)
            elif key == 'event':
                content += self.event_as_xml(document)
            elif key == 'fonts' and not 'application_name' in document.keys() and not 'directory' in document.keys():
                content += self.standalone_font_as_xml(document)
            elif key == 'forum':
                content += self.forum_as_xml(document)  
            elif key == 'glossary_term':
                content += self.glossary_as_xml(document)
            elif key == 'howto':
                content += self.howto_as_xml(document)
            elif key == 'question':
                content += self.faq_as_xml(document)
            elif key == 'magazine':
                content += self.magazine_as_xml(document)
            elif key == 'monitor_definition_files' and not 'application_name' in document.keys() and not 'directory' in document.keys():
                content += self.monitor_definition_file_as_xml(document)
            elif key == 'peripheral':
                content += self.peripheral_as_xml(document)
            elif key == 'podule':
                content += self.podule_as_xml(document)
            elif key == 'printer_definition_files' and not 'application_name' in document.keys() and not 'directory' in document.keys():
                content += self.printer_definition_file_as_xml(document)
            elif key == 'project':
                content += self.project_as_xml(document)
            elif key == 'provider':
                content += self.service_as_xml(document)
            elif key == 'relocatable_modules' and not 'application_name' in document.keys() and not 'directory' in document.keys():
                content += self.standalone_relocatable_module_as_xml(document)
            elif key == 'user_group':
                content += self.usergroup_as_xml(document)
            elif key == 'utilities' and not 'application_name' in document.keys() and not 'directory' in document.keys():
                content += self.standalone_utility_as_xml(document)
            elif key == 'video':
                content += self.video_as_xml(document)
            #endif
        #endfor
        content += '</riscos>'
        return content        
    #enddef
    
    @cherrypy.expose
    def generic_search(self, format="string", search=''):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, follow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())
                
        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            if search:
                userDocument['search_criteria'] = {}
                userDocument['key'] = ""
                userDocument['format'] = format
                userDocument['value'] = search
            #endif
            self.usersCollection.save(userDocument)
        #endif   

        content += '<h2>Generic Search</h2>'
        
        content += '<p><form action="/riscos/generic_search" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="search" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="search" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = []
            for (externalAttribute,internalAttribute,key) in self.searchableAttributes:
                attributesToSearch.append(internalAttribute)
            #endfor
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    if attributeToSearch in ['relocatable_modules','module_dependencies','utilities']:
                        searchCriteria[attributeToSearch+'.name'] = re.compile('(?i)'+search)
                    else:
                        searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    #endif
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif           
            
        #endif
        content += self.footer()
        return content
    #enddef
    
    def embed_web_sites(self, docIds):
        content = ""
        distinctUrls = []
        for docId in docIds:
            document = self.riscosCollection.find_one({'_id':ObjectId(docId),"directory":{"$exists":True,"$ne":""},"parent_url":{"$exists":True,"$ne":""}})
            if document and not document['parent_url'] in distinctUrls:
                distinctUrls.append(document['parent_url'])
            #endif
        #endfor
        distinctUrls.sort()
        for distinctUrl in distinctUrls:
            distinctApps = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""},"parent_url":distinctUrl}).distinct("directory")
            content += self.embed_web_site(distinctUrl, distinctApps)
        #endfor
        return content
    #enddef
    
    def regex_table(self):
        content = '<p><table id="regex">'
        content += '<tr><th>Special Character</th><th>Explanation</th><th>Example</th></tr>'
        content += '<tr><td>.</td><td>Matches any character except a newline</td><td></td></tr>'
        content += '<tr><td>^</td><td>Matches the start of the string</td><td>`^\!Fonts$` will match `!Fonts`</td></tr>'
        content += '<tr><td>$</td><td>Matches the end of the string</td><td>`^\!Fonts$` will match `!Fonts`</td></tr>'
        content += '<tr><td>*</td><td>Matches 0 or more repetitions of the preceding regular expression</td><td></td></tr>'
        content += '<tr><td>+</td><td>Matches 1 or more repetitions of the preceding regular expression</td><td></td></tr>'
        content += '<tr><td>?</td><td>Matches 0 or 1 repetitions of the preceding regular expression</td><td>`^\!Fonts?$` will match `!Fonts` and `!Font`</td></tr>'
        content += '<tr><td>\\</td><td>Escapes special characters</td><td>`C/C\+\+` will match `C/C++`</td></tr>'
        content += '<tr><td>[]</td><td>Used to indicate a set of characters</td><td></td></tr>'
        content += '<tr><td>|</td><td>A|B, where A and B can be arbitrary regular expressions, creates a regular expression that will match either A or B</td><td></td></tr>'
        content += '</table></p>'
        return content
    #enddef
    
    def apply_filter(self, userDocument, doc_ids):
        if userDocument and ((userDocument.has_key('riscos_version') and userDocument['riscos_version']) or (userDocument.has_key('addressing_mode') and userDocument['addressing_mode'])):
            filteredDocIds = []
            for doc_id in doc_ids:
                validDocID = False
                if userDocument.has_key('riscos_version') and userDocument['riscos_version'] and userDocument.has_key('addressing_mode') and userDocument['addressing_mode']:
                    validRiscosVersion = False
                    validAddressingMode = False
                    if self.riscosCollection.find({'_id':ObjectId(doc_id),'module_dependencies.name':'UtilityModule'}).count():
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id),'module_dependencies.name':'UtilityModule'})
                        for item in document['module_dependencies']:
                            if item.has_key('name') and item['name'] == 'UtilityModule':
                                if item.has_key('version') and item['version'] and len(item['version']) == 4 and item['version'] == userDocument['riscos_version']:
                                    validRiscosVersion = True
                                    break
                                #endif
                            #endif
                        #endfor
                    else:
                        validRiscosVersion = True
                    #endif
                    if self.riscosCollection.find({'_id':ObjectId(doc_id),'relocatable_modules.addressing_mode':{"$exists":True}}).count():
                        validAddressingMode = True
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id),'relocatable_modules.addressing_mode':{"$exists":True}})
                        for item in document['relocatable_modules']:
                            if item.has_key('addressing_mode') and item['addressing_mode'] and item['addressing_mode'] != userDocument['addressing_mode']:
                                validAddressingMode = False
                                break
                            #endif
                        #endfor
                    else:
                        validAddressingMode = True
                    #endif 
                    if validRiscosVersion and validAddressingMode:
                        validDocID = True
                    #endif                    
                elif userDocument.has_key('riscos_version') and userDocument['riscos_version']:
                    if self.riscosCollection.find({'_id':ObjectId(doc_id),'module_dependencies.name':'UtilityModule'}).count():
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id),'module_dependencies.name':'UtilityModule'})
                        for item in document['module_dependencies']:
                            if item.has_key('name') and item['name'] == 'UtilityModule':
                                if item.has_key('version') and item['version'] and len(item['version']) == 4 and item['version'] == userDocument['riscos_version']:
                                    validDocID = True
                                    break
                                #endif
                            #endif
                        #endfor
                    else:
                        validDocID = True
                    #endif          
                elif userDocument.has_key('addressing_mode') and userDocument['addressing_mode']:
                    if self.riscosCollection.find({'_id':ObjectId(doc_id),'relocatable_modules.addressing_mode':{"$exists":True}}).count():
                        validAddressingMode = True
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id),'relocatable_modules.addressing_mode':{"$exists":True}})
                        for item in document['relocatable_modules']:
                            if item.has_key('addressing_mode') and item['addressing_mode'] and item['addressing_mode'] != userDocument['addressing_mode']:
                                validAddressingMode = False
                                break
                            #endif
                        #endfor
                        if validAddressingMode:
                            validDocID = True
                        #endif
                    else:
                        validDocID = True
                    #endif                    
                else:
                    validDocID = True
                #endif
                    
                if validDocID:
                    if userDocument.has_key('territory') and userDocument['territory']:
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                        if document:
                            if document.has_key('territories') and document['territories']:
                                if not userDocument['territory'] in document['territories']:
                                    validDocID = False
                                #endif
                            #endif
                        #endif                        
                    #endif
                #endif
                    
                if validDocID: 
                    if userDocument.has_key('start_year') and userDocument['start_year'] or userDocument.has_key('end_year') and userDocument['end_year']: 
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                        if document:
                            if document.has_key('date') and document['date']:
                                try:
                                    documentYear = int(time.ctime(int(document['date']))[-4:])
                                    if documentYear < int(userDocument['start_year']) or documentYear > int(userDocument['end_year']):
                                        validDocID = False
                                    #endif
                                except:
                                    True
                            #endif
                        #endif
                    #endif
                #endif
                
                if validDocID: 
                    if userDocument.has_key('arm_architecture') and userDocument['arm_architecture']: 
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                        if document:
                            if document.has_key('arm_architectures') and document['arm_architectures']:
                                if not userDocument['arm_architecture'] in document['arm_architectures']:
                                    validDocID = False
                                #endif
                            #endif
                        #endif
                    #endif
                #endif
                
                if validDocID:
                    filteredDocIds.append(doc_id)
                #endif
            #endfor
        else:
            filteredDocIds = doc_ids
        #endif    
        return filteredDocIds
    #endif
    
    @cherrypy.expose
    def advanced_search(self, attribute='directory', value='', nested=False, removal=False, spider=False):
        status = self.cookie_handling()
        content = ""
               
        if removal:
            nested = True
        elif not value and nested:
            nested = False
        #endif
               
        content += self.header(status, 'index, nofollow')  
        
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        
        epoch = int(time.time())
        
        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
        
            if value:
                if attribute:
                    if nested:
                        if userDocument.has_key('search_criteria'):
                            searchCriteria = userDocument['search_criteria']
                        else:
                            searchCriteria = {}
                        #endif
                        searchCriteria[attribute] = value
                        userDocument['search_criteria'] = searchCriteria
                        userDocument['key'] = attribute
                        userDocument['value'] = value
                    else:
                        userDocument['search_criteria'] = {}
                        userDocument['key'] = attribute
                        userDocument['value'] = value
                    #endif
                else:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = value
                #endif
            #endif
            self.usersCollection.save(userDocument)

            if not attribute and not value:
                if userDocument and userDocument.has_key('key') and userDocument['key']:
                    attribute = userDocument['key']
                #endif
                if userDocument and userDocument.has_key('value') and userDocument['value']:
                    value = userDocument['value']
                #endif
            #endif
        
            if userDocument['user_agent'].__contains__('Googlebot'):
                spider = True
            #endif
        #endif        
        
        if spider:
            latestMessage = self.riscosspider.spider()
            if latestMessage:
                content += '<h3 id="infobar">'+latestMessage+'</h3>'
            #endif
        #endif
        
        content += '<h2>Advanced Search</h2>'
        
        if userDocument and nested:
            content += '<br><table id="searchcriteria"><thead><tr><th colspan="3">Nested Search Criteria</th></tr></thead><tbody>'
            for key in userDocument['search_criteria']:
                content += '<tr><th>'+key+'</th><td>'+userDocument['search_criteria'][key]+'</td><td><form class="inline" action="/riscos/remove_search_component" method="post"><input type="hidden" name="attribute" value="'+key+'"><input type="hidden" name="value" value="'+userDocument['search_criteria'][key]+'"><input class="watchlist" type="submit" value="Remove"></form></td></tr>'
            #endfor
            content += '</tbody></table>'
        #endif
        
        content += '<p><form action="/riscos/advanced_search" method="post">'
        
        content += '<select class="search" name="attribute">'
        for (externalAttribute,internalAttribute,key) in self.searchableAttributes:
            if internalAttribute == attribute:
                content += '<option value="'+internalAttribute+'" selected>'+externalAttribute+'</option>'
            else:
                content += '<option value="'+internalAttribute+'">'+externalAttribute+'</option>'
            #endif
        #endfor
        content += '</select> '        

        if value:
            content += '<input id="search" type="text" size="40" name="value" value="'+value+'">'
        else:
            content += '<input id="search" type="text" size="40" name="value">'
        #endif
        
        if nested:
            content += '<input type="checkbox" name="nested" title="Select to start a complex search" checked> Nested '
        else:
            content += '<input type="checkbox" name="nested" title="Select to start a complex search"> Nested '
        #endif     
        
        content += '<input type="checkbox" name="spider" title="Combine your search with a single spidering iteration"> Spider '
        
        content += '<input class="button" type="submit" value="Search">'
        
        content += '</form></p>'

        if value:
            count = 0
            
            if nested and userDocument and userDocument.has_key('search_criteria') and userDocument['search_criteria']:
                searchCriteria = {}
                for attribute in userDocument['search_criteria']:
                    try:
                        if attribute in ['relocatable_modules','module_dependencies','utilities']:
                            searchCriteria[attribute+'.name'] = re.compile('(?i)'+userDocument['search_criteria'][attribute])
                        else:
                            searchCriteria[attribute] = re.compile('(?i)'+userDocument['search_criteria'][attribute])
                        #endif
                    except:
                        content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+userDocument['search_criteria'][attribute]+"`, your Regex for `"+attribute+"`!</h3>"
                        for charToBeEscaped in ['\\','(',')','$','.','+']:
                            if charToBeEscaped in userDocument['search_criteria'][attribute] and not '\\'+charToBeEscaped in userDocument['search_criteria'][attribute]:
                                content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+userDocument['search_criteria'][attribute].replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                            #endif
                        #endfor
                        content += self.regex_table()
                        content += self.footer()
                        return content                    
                #endfor
                doc_ids = self.riscosCollection.find(searchCriteria).distinct('_id')
            else:
                doc_ids = []
                if attribute:
                    attributesToSearch = [attribute]
                else:
                    attributesToSearch = []
                    for (externalAttribute,internalAttribute,key) in self.searchableAttributes:
                        attributesToSearch.append(internalAttribute)
                    #endfor
                #endif
                for attributeToSearch in attributesToSearch:
                    searchCriteria = {}
                    try:
                        if attributeToSearch in ['relocatable_modules','module_dependencies','utilities']:
                            searchCriteria[attributeToSearch+'.name'] = re.compile('(?i)'+value)
                        else:
                            searchCriteria[attributeToSearch] = re.compile('(?i)'+value)
                        #endif
                        doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    except:
                        content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in '"+value+"', your Regex for '"+attributeToSearch+"'!"
                        for charToBeEscaped in ['\\','(',')','$','.','+']:
                            if charToBeEscaped in value and not '\\'+charToBeEscaped in value:
                                content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+value.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                            #endif
                        #endfor
                        content += "</h3>"
                        content += self.regex_table()
                        content += self.footer()
                        return content
                #endfor                
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'advanced_search', nested)
            else:
                content += self.display_document_report(filteredDocIds, 'advanced_search', nested)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
            
        #endif
        content += self.footer()
        return content
    #enddef

    def filter_documents_by_type(self, doc_ids, type):
        filteredDocIds = []
        discarded = 0
        doc_ids = list(set(doc_ids))
        if type == 'Applications':
            for doc_id in doc_ids:
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    if document.has_key('directory') and document['directory']:
                        if not document.has_key('superseded_by') or not document['superseded_by']:
                            filteredDocIds.append(doc_id)
                        #endif
                    #endif            
                #endif
            #endfor
            for doc_id in doc_ids:
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    if document.has_key('directory') and document['directory']:
                        if document.has_key('superseded_by') and document['superseded_by']:
                            filteredDocIds.append(doc_id)
                        #endif
                    #endif            
                #endif
            #endfor             
        elif type == 'CompressedFiles':
            for doc_id in doc_ids:
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    if not (document.has_key('directory') and document['directory']):
                        if (document.has_key('zip_file') and document['zip_file']) or (document.has_key('arc_file') and document['arc_file']) or (document.has_key('spk_file') and document['spk_file']):
                            filteredDocIds.append(doc_id)
                        #endif
                    #endif             
                #endif
            #endfor        
        elif type == 'Non-Software':
            for doc_id in doc_ids:
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    if not (document.has_key('directory') and document['directory']):
                        if not(document.has_key('zip_file') and document['zip_file']):
                            if not (document.has_key('arc_file') and document['arc_file']):
                                if not (document.has_key('spk_file') and document['spk_file']):
                                    filteredDocIds.append(doc_id)
                                #endif
                            #endif
                        #endif
                    #endif           
                #endif
            #endfor        
        #endif

        if len(filteredDocIds) >= 32:
            discarded = len(filteredDocIds)-32
            filteredDocIds = filteredDocIds[:32]
        #endif
        return filteredDocIds, discarded
    #enddef
    
    def display_document_table(self, doc_ids, origin, nested=False):
        content = ""
        romModules = []
        epoch = int(time.time())
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        
        selectedRiscosVersion, selectedAddressingMode, selectedArmArchitecture, selectedTerritory, selectedStartYear, selectedEndYear, selectedView, selectedWebsites = self.get_filter_settings(userDocument) 
        for (potentialRiscosVersion,potentialRomModules) in self.romModules:
            if selectedRiscosVersion == potentialRiscosVersion:
                romModules = potentialRomModules
                break
            #endif
        #endfor      
        
        if doc_ids:
            for (type,textualType) in [('Applications','RISC OS Applications'),('CompressedFiles','Miscellaneous Archive Files'),('Non-Software','Non-Software URLs')]:
                filteredDocIds, discarded = self.filter_documents_by_type(doc_ids, type)

                if filteredDocIds:              
                
                    #content += '<h2 class="resultheader">'+textualType+'</h2>'
                
                    columnsRequired = []
                    for doc_id in filteredDocIds:
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                        if document:
                            for (externalAttribute,internalAttribute,image) in self.displayedAttributes:
                                if not internalAttribute in columnsRequired:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        columnsRequired.append(internalAttribute)
                                    #endif
                                #endif
                            #endfor
                        #endif
                    #endfor

                    content += '<table class="software">'
                    content += '<tr>'
                    for (externalAttribute,internalAttribute,image) in self.displayedAttributes:
                        if internalAttribute in columnsRequired:
                            content += '<th><p class="heading">'
                            if image:
                                content += '<img class="headingicon" src="/riscos/images/'+image+'" alt="'+image+'">'
                            #endif
                            content += externalAttribute
                            content += '</p></th>'
                        #endif
                    #endfor
                    content += '<th><p class="heading">Buttons</p></th></tr>'

                    for doc_id in filteredDocIds:
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                        if document.has_key('superseded_by') and document['superseded_by']:
                            content += '<tr class="superseded">'
                        else:
                            content += '<tr>'
                        #endif
                        for (externalAttribute,internalAttribute,image) in self.displayedAttributes:
                            if internalAttribute in columnsRequired:
                                if internalAttribute in ['page_title']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        if document.has_key('url') and document['url']:
                                            content += '<td valign="top"><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document[internalAttribute]+'</a></td>'
                                        else:
                                            content += '<td valign="top">'+document[internalAttribute]+'</td>'
                                        #endif
                                    else:
                                        content += '<td></td>'
                                    #endif        
                                    
                                elif internalAttribute in ['application_name','syndicated_feed_item_description']:        
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><b>'+document[internalAttribute]+'</b></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
                                    
                                elif internalAttribute in ['directory','syndicated_feed_item_title']:      
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><p>'
                                        if document.has_key('icon_url') and document['icon_url']:
                                            content += '<img src="'+document['icon_url']+'"><br>'
                                        #endif
                                        content += '<b>'+document[internalAttribute]+'</b></p></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif                                   

                                elif internalAttribute == 'description':        
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><p align="left">'+document[internalAttribute]+'</p>'
                                        if document.has_key('image_url') and document['image_url']:
                                            content += '<p><img src="'+document['image_url']+'"></p>'
                                        #endif
                                        if document.has_key('advert_url') and document['advert_url']:
                                            content += '<p><img src="'+document['advert_url']+'"></p>'
                                        #endif                                        
                                        content += '</td>'
                                    elif document.has_key('image_url') and document['image_url']:
                                        content += '<td valign="top"><img src="'+document['image_url']+'"></td>'
                                    elif document.has_key('advert_url') and document['advert_url']:
                                        content += '<td valign="top"><img src="'+document['advert_url']+'"></td>'
                                    else:                                       
                                        content += '<td></td>'
                                    #endif
                                    
                                elif internalAttribute == 'application_version':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        if document.has_key('superseded_by') and document['superseded_by']:
                                            if self.riscosCollection.find({'_id':ObjectId(document['superseded_by'])}).count():
                                                otherDocument = self.riscosCollection.find_one({'_id':ObjectId(document['superseded_by'])})
                                                if otherDocument.has_key('application_version') and otherDocument['application_version']:
                                                    content += '<td valign="top">'+document[internalAttribute]+'<br><b class="error">Superseded by '+otherDocument['application_version']+'</b></td>'
                                                else:
                                                    content += '<td valign="top">'+document[internalAttribute]+'<br><b class="error">Possibly superseded!</b></td>'
                                                #endif
                                            else:
                                                content += '<td valign="top"><b>'+document[internalAttribute]+'</b></td>'
                                            #endif
                                        else:
                                            content += '<td valign="top"><b>'+document[internalAttribute]+'</b></td>'
                                        #endif
                                    else:
                                        content += '<td></td>'
                                    #endif                                
                                        
                                elif internalAttribute == 'date':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        try:
                                            timeString = time.ctime(int(document['date']))
                                            content += '<td valign="top"><sub>'+timeString+'</sub></td>'
                                        except:
                                            content += '<td valign="top"><sub>'+document[internalAttribute]+'</sub></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
                                        
                                elif internalAttribute == 'last_scanned':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        timeString = time.ctime(int(document['last_scanned']))
                                        content += '<td valign="top"><sub>'+timeString+'</sub>'
                                        content += '</td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
                                    
                                elif internalAttribute == 'next_scan':
                                    content += '<td valign="top">'
                                    if document.has_key('next_scan') and document['next_scan']:
                                        difference = int(document['next_scan'])-epoch
                                        noOfDays = int(difference/86400)
                                        timeString = time.ctime(int(document['next_scan']))
                                        content += '<sub>In '+str(noOfDays)+' Days<br>' + timeString+'</sub><br>'
                                    #endif
                                    # If document is over a year old, provide a 'Rescan' button
                                    if document.has_key('last_scanned') and epoch-31536000 > document['last_scanned']:
                                        if userDocument and ((userDocument.has_key('rescan_count') and userDocument['rescan_count'] < 10) or (not userDocument.has_key('rescan_count'))):
                                            content += '<form class="inline" action="/riscos/rescan" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input type="hidden" name="origin" value="'+origin+'"><input class="rescan" type="submit" value="Rescan" title="Mark the document to be rescanned at the next opportunity"></form>'
                                        #endif
                                    #endif
                                    content += '</td>'
                                        
                                elif internalAttribute == 'url':
                                    if document.has_key('video') and document['video']:
                                        content += '<td valign="top"><iframe width="560" height="315" src="'+document['url']+'" frameborder="0" allowfullscreen></iframe></td>'
                                    else:
                                        if document.has_key(internalAttribute) and document[internalAttribute]:
                                            if document[internalAttribute].lower().endswith('.zip'):
                                                if document.has_key('zip_file') and not document[internalAttribute].lower().__contains__('/softwareunconfirmed/'):
                                                    if document.has_key('application_name') and document['application_name']:
                                                        title = "Download "+document['application_name']
                                                    elif document.has_key('directory') and document['directory']:
                                                        title = "Download "+document['directory']
                                                    else:
                                                        title = "Download "+document['zip_file']
                                                    #endif
                                                    content += '<td valign="top"><a href="'+document[internalAttribute]+'" target="_blank" title="'+document[internalAttribute]+'"><img src="/riscos/images/ddc.png" alt="ddc" title="'+title+'"></a></td>'
                                                else:
                                                    content += '<td></td>'
                                                #endif
                                            elif document[internalAttribute].lower().endswith('.arc') or document[internalAttribute].lower().endswith('.spk') or document[internalAttribute].lower().endswith('.pdf'): 
                                                content += '<td valign="top"><a href="'+document[internalAttribute]+'" target="_blank" title="'+document[internalAttribute]+'">'+document[internalAttribute]+'</a></td>'
                                            else:
                                                content += '<td valign="top"><a href="'+document[internalAttribute]+'" target="_blank" title="'+document[internalAttribute]+'"><img src="/riscos/images/url.gif"></a></td>'
                                            #endif
                                        else:
                                            content += '<td></td>'
                                        #endif
                                    #endif
                                    
                                elif internalAttribute == 'parent_url':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td align="center" valign="top"><a href="'+document[internalAttribute]+'" target="_blank" title="'+document[internalAttribute]+'"><img src="/riscos/images/url.gif"></a></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
        
                                elif internalAttribute in ['riscos_versions']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:
                                            if item <= 3.99:
                                                content += '<li>RISC OS '+str(item)+' (Legacy Acorn Computers)</li>'
                                            elif item >= 4.00 and item <= 4.99:
                                                content += '<li>RISC OS '+str(item)+' (RISCOS Ltd/3QD Developments Ltd)</li>'
                                            elif item >= 5.00 and item <= 5.99:
                                                content += '<li>RISC OS '+str(item)+' (Castle Technology/RISC OS Open Ltd)</li>'
                                            elif item >= 6.00 and item <= 6.99:
                                                content += '<li>RISC OS '+str(item)+' (RISCOS Ltd/3QD Developments Ltd)</li>'
                                            #endif
                                        #endfor
                                        content += '</ul></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif  
                                    
                                    #elif internalAttribute == 'module_dependencies':
                                    #    if document.has_key(internalAttribute) and document[internalAttribute]:
                                    #        content += '<td valign="top"><ul>'
                                    #        for item in document[internalAttribute]:
                                    #            if romModules:
                                    #                presentAsRomModule = False
                                    #                for (potentialRomModuleName,potentialRomModuleVer) in romModules:
                                    #                    if item == potentialRomModuleName+' '+potentialRomModuleVer:
                                    #                        presentAsRomModule = True
                                    #                        break
                                    #                    #endif
                                    #                #endfor
                                    #                if not presentAsRomModule:
                                    #                    content += '<li>'+item.replace(' ','&nbsp;')+'</li>'
                                    #                #endif
                                    #            else:
                                    #                content += '<li>'+item.replace(' ','&nbsp;')+'</li>'
                                    #            #endif
                                    #        #endfor
                                    #        content += '</ul></td>'
                                    #    else:
                                    #        content += '<td></td>'
                                    #    #endif  
                                    
                                elif internalAttribute == 'help':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        helpText = document[internalAttribute]
                                        helpText = helpText.replace('(C)','&copy;')
                                        helpText = helpText.replace('RiscOs','RISC OS')
                                        helpText = helpText.replace('RiscOS','RISC OS')
                                        helpText = helpText.replace('RISC-OS','RISC OS')
                                        helpText = helpText.replace('Risc Os','RISC OS')
                                        helpText = helpText.replace('<','&lt;')
                                        helpText = helpText.replace('>','&gt;')
                                        content += '<td valign="top"><textarea rows="10" cols="40" readonly>'+helpText+'</textarea></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif

                                elif internalAttribute in ['arm_architectures','authors','programming_languages']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:
                                            modifiedItem = item.replace(' ','&nbsp;')
                                            content += '<li>'+modifiedItem+'</li>'
                                        #endfor
                                        content += '</ul></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif 
                                    
                                elif internalAttribute in ['filetypes_set']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:                                            
                                            content += '<li><a href="/riscos/filetype?search='+item+'">'+item.replace(' ','&nbsp;')+'</a></li>'
                                        #endfor
                                        content += '</ul></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif  
                                    
                                elif internalAttribute in ['absolutes','categories','dtp_formats','filetypes_run','fonts','monitor_definition_files','printer_definition_files','territories','system_variables']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:
                                            content += '<li>'+item+'</li>'
                                        #endfor
                                        content += '</ul></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif                                
        
                                elif internalAttribute in ['relocatable_modules','utilities','pricing']:
                                    if document.has_key(internalAttribute) and (isinstance(document[internalAttribute],dict) or isinstance(document[internalAttribute],list) or isinstance(document[internalAttribute][0],str)):
                                        content += '<td valign="top">'
                                        if isinstance(document[internalAttribute][0],dict):
                                            potentialColumns = [('Name','name'),('Type','type'),('Ver','version'),('Addr Mode','addressing_mode'),('From','from'),('To','to'),('Currency','currency'),('Duration','duration'),('Price','price'),('Syntax','syntax'),('Star Commands','star_commands')]
                                            columnsToDisplay = []
                                            for (potentialColumnHeading,potentialColumnDBField) in potentialColumns:
                                                for subDocument in document[internalAttribute]:
                                                    if subDocument.has_key(potentialColumnDBField) and subDocument[potentialColumnDBField]:
                                                        if not (potentialColumnHeading,potentialColumnDBField) in columnsToDisplay:
                                                            columnsToDisplay.append((potentialColumnHeading,potentialColumnDBField))
                                                        #endif
                                                    #endif
                                                #endfor
                                            #endfor
                                            content += '<table class="embedded"><tr>'
                                            for (columnHeading,columnDBField) in columnsToDisplay:
                                                content += '<th>'+columnHeading+'</th>'
                                            #endfor
                                            content += '</tr>'
                                            for subDocument in document[internalAttribute]:
                                                content += '<tr>'
                                                for (columnHeading,columnDBField) in columnsToDisplay:
                                                    if subDocument.has_key(columnDBField) and subDocument[columnDBField]:
                                                        content += '<td>'+str(subDocument[columnDBField])+'</td>'
                                                    else:
                                                        content += '<td></td>'
                                                    #endif
                                                #endfor
                                                content += '</tr>'
                                            #endfor
                                            content += '</table>'
                                        elif isinstance(document[internalAttribute][0],list):
                                            content += 'This is a list!'
                                        elif isinstance(document[internalAttribute][0],str):
                                            content += '<ul>'
                                            for item in document[internalAttribute]:
                                                content += '<li>'+item.replace(' ','&nbsp;')+'</li>'
                                            #endfor
                                            content += '</ul>'
                                        #endif
                                        content += '</td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
        
                                elif internalAttribute in ['module_dependencies']:
                                    if document.has_key(internalAttribute) and (isinstance(document[internalAttribute],dict) or isinstance(document[internalAttribute],list) or isinstance(document[internalAttribute][0],str)):
                                        content += '<td valign="top">'
                                        if isinstance(document[internalAttribute][0],dict):
                                            potentialColumns = [('Name','name'),('Ver','version'),('Addr Mode','addressing_mode')]
                                            columnsToDisplay = []
                                            for (potentialColumnHeading,potentialColumnDBField) in potentialColumns:
                                                for subDocument in document[internalAttribute]:
                                                    if subDocument.has_key(potentialColumnDBField) and subDocument[potentialColumnDBField]:
                                                        if not (potentialColumnHeading,potentialColumnDBField) in columnsToDisplay:
                                                            columnsToDisplay.append((potentialColumnHeading,potentialColumnDBField))
                                                        #endif
                                                    #endif
                                                #endfor
                                            #endfor
                                            content += '<table class="embedded"><tr>'
                                            for (columnHeading,columnDBField) in columnsToDisplay:
                                                content += '<th>'+columnHeading+'</th>'
                                            #endfor
                                            content += '</tr>'
                                            for subDocument in document[internalAttribute]:
                                                content += '<tr>'
                                                for (columnHeading,columnDBField) in columnsToDisplay:
                                                    if subDocument.has_key(columnDBField) and subDocument[columnDBField]:
                                                        if columnDBField == 'name':
                                                            content += '<td><a href="/riscos/module?search='+str(subDocument[columnDBField])+'">'+str(subDocument[columnDBField])+'</a></td>'
                                                        else:
                                                            content += '<td>'+str(subDocument[columnDBField])+'</td>'
                                                        #endif
                                                    else:
                                                        content += '<td></td>'
                                                    #endif
                                                #endfor
                                                content += '</tr>'
                                            #endfor
                                            content += '</table>'
                                        elif isinstance(document[internalAttribute][0],str):
                                            content += '<ul>'
                                            for item in document[internalAttribute]:
                                                content += '<li>'+item.replace(' ','&nbsp;')+'</li>'
                                            #endfor
                                            content += '</ul>'
                                        elif isinstance(document[internalAttribute][0],list):
                                            content += 'This is a list!'
                                        #endif
                                        content += '</td>'
                                    else:
                                        content += '<td></td>'
                                    #endif    
                                    
                                elif document.has_key(internalAttribute) and document[internalAttribute]:
                                    try:
                                        content += '<td valign="top">'+str(document[internalAttribute])+'</td>'
                                    except:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:
                                            content += '<li>'+item+'</li>'
                                        #endfor
                                        content += '</ul></td>'
                                    #endtryexcept
        
                                else:
                                    content += '<td></td>'                       
                                #endif
                            #endif
                        #endfor
                        content += '<td valign="top">'
                        
                        if userDocument.has_key('watchlist') and str(document['_id']) in userDocument['watchlist']:
                            content += '<form class="inline" action="/riscos/remove_from_watchlist" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input type="hidden" name="origin" value="'+origin+'">'
                            if nested:
                                content += '<input type="hidden" name="nested" value="true">'
                            #endif                     
                            content += '<input class="watchlist" type="submit" value="Remove" title="Remove from watchlist"></form>'
                        else:
                            content += '<form class="inline" action="/riscos/add_to_watchlist" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input type="hidden" name="origin" value="'+origin+'">'
                            if nested:
                                content += '<input type="hidden" name="nested" value="true">'
                            #endif
                            content += '<input class="watchlist" type="submit" value="Watch" title="Add to watchlist"></form>'
                            content += '<form class="inline" action="/riscos/record_as_xml" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input class="watchlist" type="submit" value="XML" title="View record in riscos.xml format"></form>'
                            content += '<form class="inline" action="/riscos/record_as_json" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input class="watchlist" type="submit" value="JSON" title="View record in JSON format"></form>'
                            if document.has_key('url') and document['url']:
                                (scheme,netloc,path,query,fragment) = urlparse.urlsplit(document['url'])
                                if not self.trusted_domains.has_key(netloc):
                                    content += '<form class="inline" action="/riscos/report_abuse" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input class="watchlist" type="submit" value="Abuse" title="Quarantine by reporting as abuse"></form>'
                                #endif
                            else:
                                content += '<form class="inline" action="/riscos/report_abuse" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input class="watchlist" type="submit" value="Abuse" title="Quarantine by reporting as abuse"></form>'
                            #endif
                        #endif
                        content += '</td>'
                    #endfor
                        
                    if discarded:
                        content += '<tr><td colspan="'+str(len(columnsRequired)+1)+'"><h3 class="warning">Sorry, Unable To Display Remaining '+str(discarded)+' Records!</h3></td></tr>'
                    #endif
                    content += '</table>'
                    
                    if type == 'Applications':
                        if userDocument and userDocument.has_key('web_sites') and userDocument['web_sites'] and userDocument['web_sites'] in ['enabled 640x480','enabled 800x600','enabled 1024x768']:
                            content += self.embed_web_sites(filteredDocIds)
                        #endif
                    #endif
                    content += '<p></p>'
                #endif
            #endfor
        else:
            content += '<p align="center"><b>Sorry, no matching records could be found!<br>Ensure the above filter is set correctly!<br>Should you find the information you require elsewhere,<br>please don\'t forget to submit the URL to us for the benefit of others!</b></p>'
            content += '<p align="center">You might like to try: <a href="http://www.filebase.org.uk/">ANS RISC OS Filebase</a> | <a href="http://www.riscos.org/links/">RISC OS Software Links Database</a> | <a href="http://nutshells.anjackson.net/">Nutshells</a> | <a href="http://www.arcsite.de/arcarchie/eindex.html">ArcArchie</a> | <a href="http://www.riscos.com/the_archive/rol/productsdb/index.htm">RISC OS Products Directory</a></p>'
        #endif
        return content
    #enddef
    
    def display_document_report(self, doc_ids, origin, nested=False):
        content = ""
        romModules = []
        
        remoteAddr = cherrypy.request.remote.ip
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        
        selectedRiscosVersion, selectedAddressingMode, selectedArmArchitecture, selectedTerritory, selectedStartYear, selectedEndYear, selectedView, selectedWebsites = self.get_filter_settings(userDocument)
        for (potentialRiscosVersion,potentialRomModules) in self.romModules:
            if selectedRiscosVersion == potentialRiscosVersion:
                romModules = potentialRomModules
                break
            #endif
        #endfor       
        
        content += '<div class="report">'
        if doc_ids:
            for (type,textualType) in [('Applications','RISC OS Applications'),('CompressedFiles','Miscellaneous Archive Files'),('Non-Software','Non-Software URLs')]:
                filteredDocIds, discarded = self.filter_documents_by_type(doc_ids, type)
                if filteredDocIds:
                
                    #content += '<h2 class="resultheader">'+textualType+'</h2>'
                    
                    for doc_id in filteredDocIds:
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                        if document.has_key('url') and document['url'] and not document['url'].__contains__('/riscos/softwareunconfirmed/'):
                            if (document.has_key('directory') and document['directory']) or (document.has_key('application_name') and document['application_name']):
                                if document.has_key('directory') and document['directory'] and document.has_key('application_name') and document['application_name']:
                                    content += '<p class="report"><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_name']+'</a> ('+document['directory']+')'+self.insert_application_version_and_or_date(document)+self.insert_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                elif document.has_key('directory') and document['directory']:
                                    content += '<p class="report"><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['directory']+'</a>'+self.insert_application_version_and_or_date(document)+self.insert_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                elif document.has_key('application_name') and document['application_name']:
                                    content += '<p class="report"><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_name']+'</a>'+self.insert_application_version_and_or_date(document)+self.insert_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                #endif
                                distinctModules = self.riscosCollection.find({'_id':ObjectId(document['_id'])}).distinct('relocatable_modules.name')
                                if distinctModules:
                                    content += '<br>Modules: '
                                    try:
                                        for i in range(len(distinctModules)):
                                            content += '<a href="/riscos/module?search='+distinctModules[i]+'">'+distinctModules[i]+'</a>'
                                            if i < len(distinctModules)-1:
                                                content += ', '
                                            #endif
                                        #endfor
                                    except:
                                        True
                                #endif
                            elif document.has_key('domain') and document['domain'] in ['www.youtube.com','m.youtube.com','uk.youtube.com'] and document.has_key('embed') and document['embed']:
                                if document.has_key('page_title') and document['page_title']:
                                    content += '<p class="report">'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+self.insert_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                else:
                                    content += '<p class="report">'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['url']+'</a>'+self.insert_parent_hyperlink(document)+self.insert_date(document)
                                #endif
                            elif document.has_key('page_title') and document['page_title']:
                                content += '<p class="report"><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+self.insert_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                            else:   
                                content += '<p class="report"><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['url']+'</a>'+self.insert_parent_hyperlink(document)+self.insert_date(document)
                            #endif
                            content += '</p>'
                        #endif
                    #endfor
                    if type == 'Applications':
                        if userDocument and userDocument.has_key('web_sites') and userDocument['web_sites'] and userDocument['web_sites'] in ['enabled 640x480','enabled 800x600','enabled 1024x768']:
                            content += self.embed_web_sites(filteredDocIds)
                        #endif
                    #endif
                #endif
                content += '<p></p>'
            #endfor
        else:
            content += '<p align="center"><b>Sorry, no matching records could be found!<br>Ensure the above filter is set correctly!<br>Should you find the information you require elsewhere,<br>please don\'t forget to submit the URL to us for the benefit of others!</b></p>'
            content += '<p align="center">You might like to try: <a href="http://www.filebase.org.uk/">ANS RISC OS Filebase</a> | <a href="http://www.riscos.org/links/">RISC OS Software Links Database</a> | <a href="http://nutshells.anjackson.net/">Nutshells</a> | <a href="http://www.arcsite.de/arcarchie/eindex.html">ArcArchie</a> | <a href="http://www.riscos.com/the_archive/rol/productsdb/index.htm">RISC OS Products Directory</a></p>'
        #endif
        content += '</div>'
        return content
    #enddef
    
    def insert_parent_hyperlink(self,document):
        content = ""
        if document.has_key('parent_url') and document['parent_url']:
            content += ' <sup><a href="'+document['parent_url']+'" target="_blank">Parent</a></sup>'
        #endif
        return content
    #enddef
    
    def insert_application_version_and_or_date(self,document):
        content = ""
        if (document.has_key('application_version') and document['application_version']) or (document.has_key('date') and document['date']):
            if document.has_key('application_version') and document['application_version'] and document.has_key('date') and document['date']:
                tuple = time.localtime(document['date'])
                month = self.months[tuple[1]-1]
                content += ' '+document['application_version']+' ('+str(tuple[2])+'-'+month+'-'+str(tuple[0])+')'
            elif document.has_key('application_version') and document['application_version']:
                content += ' '+document['application_version']
            elif document.has_key('date') and document['date']:
                tuple = time.localtime(document['date'])
                month = self.months[tuple[1]-1]
                content += ' ('+str(tuple[2])+'-'+month+'-'+str(tuple[0])+')'
            #endif
        #endif
        return content
    #enddef    
    
    def insert_date(self,document):
        content = ""
        if document.has_key('date') and document['date']:
            try:
                timeString = time.ctime(int(document['date']))
                content += ' <b class="inverse">'+timeString+'</b>'
            except:
                content += ''
        #endif
        return content
    #enddef
    
    @cherrypy.expose
    def sourcecode(self, nested=False):
        status = self.cookie_handling()
        content = ""
        port = ""
        content += self.header(status, 'noindex, follow')
        
        content += '<p>The source code to the RISC OS Search Engine project can be found on <a href="https://github.com/RebeccaShalfield/RISCOSSearchEngine">GitHub</a></p>'
        
        for sourceCodeFile in ['riscos.py','riscosspider.py','riscossoftware.py']:
            ip = open(self.path+os.sep+sourceCodeFile)
            sourceCode = ip.read()
            ip.close()
            sourceCode = sourceCode.replace('&','&amp;')
            sourceCode = sourceCode.replace('<','&lt;')
            sourceCode = sourceCode.replace('>','&gt;')
            content += '<h3>'+sourceCodeFile+'</h3>'
            content += '<table class="sourcecode"><tr><td><pre>'+sourceCode+'</pre></td></tr></table>'
        #endfor
        content += '</div></body>'
        content += self.footer()
        return content  
    #enddef 
       
    @cherrypy.expose
    # This feature is hidden in the UI
    def database_as_json(self, nested=False):
        status = self.cookie_handling()
        content = ""
        port = ""
        content += self.header(status, 'noindex, follow')
        if self.mongodbPort != 27017:
            port = ' --port '+str(self.mongodbPort)
        #endif
        executable = r'"C:\Program Files\MongoDB\bin\mongoexport.exe" --verbose'+port+' --db riscos --collection riscos --out '+self.path+os.sep+'downloads'+os.sep+'riscos.json'
        (status,output) = self.getstatusoutput(executable)
        content += '<p><a href="/riscos/downloads/riscos.json">Download Database in JSON Format</p>'
        content += '</div></body>'
        content += self.footer()
        return content  
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
    
    @cherrypy.expose
    def news(self):
        epoch = int(time.time())
        status = self.cookie_handling()
        content = ""
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += self.header(status, 'index, nofollow')
        content += '<h2>News</h2>'    
        content += '<p>An amalgamation of Syndicated (RSS and Atom) Feeds from around the World Wide Web</p>'
        content += '<table border="0" width="99%"><tr>'
        colCount = 0
        for document in self.riscosCollection.find({'syndicated_feed':{'$exists':True},'date':{'$exists':True,'$ne':"",'$gte':epoch-self.periodYear}}):
            content += '<td valign="top" width="33%">'
            content += '<div class="partition">'
            if document.has_key('syndicated_feed_item_title') and document['syndicated_feed_item_title']:
                content += '<h3>'+document['syndicated_feed_item_title']+'</h3>'
            #endif
            if document.has_key('syndicated_feed_item_description') and document['syndicated_feed_item_description']:
                if document['syndicated_feed_item_description'].__contains__('</p>'):
                    content += document['syndicated_feed_item_description']
                else:
                    content += '<p align="left">'+document['syndicated_feed_item_description']+'</p>'
                #endif
            #endif
            content += '<p align="right">'
            if document.has_key('date') and document['date']:
                timeString = time.ctime(int(document['date']))
                content += timeString
            #endif
            if (document.has_key('url') and document['url']) or (document.has_key('parent_url') and document['parent_url']):
                content += " | "
            #endif
            if document.has_key('url') and document['url']:
                content += '<a href="'+document['url']+'" title="'+document['url']+'">Link</a>'
            #endif
            if document.has_key('url') and document['url'] and document.has_key('parent_url') and document['parent_url']:
                content += " | "
            #endif
            if document.has_key('parent_url') and document['parent_url']:
                content += '<a href="'+document['parent_url']+'" title="'+document['parent_url']+'">Source</a>'
            #endif
            content += '</p>'
            content += '</div>'
            content += '</td>'
            colCount += 1
            if colCount == 3:
                content += '</tr><tr>'
                colCount = 0
            #endif
        #endfor
        content += '</tr></table>'
        
        content += '<p><form class="inline" action="/riscos/syndicated_feeds" method="post"><input class="button" type="submit" value="Syndicated Feeds"></form></p>'
        
        content += self.footer()
        return content
    #enddef
    
    def latest_records(self):
        content = ""
        epoch = int(time.time())
        # Gather records last modified in the past month
        lastModifieds = self.riscosCollection.find({'date':{'$exists':True,'$ne':"",'$gte':epoch-self.periodMonth}}).distinct('date')
        lastModifieds.sort(reverse=True)
        count = 0
        for lastModified in lastModifieds:
            timeString = time.ctime(lastModified)
            # Ensure date last modified and last_scanned dates are at least two hours apart
            for document in self.riscosCollection.find({'date':lastModified,'last_scanned':{'$gt':lastModified+7200}}):
                if document.has_key('url') and document['url'] and not document['url'].__contains__('/riscos/softwareunconfirmed/'):
                    if (document.has_key('directory') and document['directory']) or (document.has_key('application_name') and document['application_name']):
                        content += ' <h4 align="left">'+timeString+'</h4>'
                        if document.has_key('directory') and document['directory'] and document.has_key('application_name') and document['application_name']:
                            content += '<p><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_name']+'</a> ('+document['directory']+')'+self.insert_application_version_and_or_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                        elif document.has_key('directory') and document['directory']:
                            content += '<p><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['directory']+'</a>'+self.insert_application_version_and_or_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                        elif document.has_key('application_name') and document['application_name']:
                            content += '<p><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_name']+'</a>'+self.insert_application_version_and_or_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                        #endif
                        distinctModules = self.riscosCollection.find({'_id':ObjectId(document['_id'])}).distinct('relocatable_modules.name')
                        if distinctModules:
                            content += '<br>Modules: '
                            try:
                                for i in range(len(distinctModules)):
                                    content += '<a href="/riscos/module?search='+distinctModules[i]+'">'+distinctModules[i]+'</a>'
                                    if i < len(distinctModules)-1:
                                        content += ', '
                                    #endif
                                #endfor
                            except:
                                True
                        #endif
                        content += '</p>'
                        count += 1
                    elif document.has_key('domain') and document['domain'] in ['www.youtube.com','m.youtube.com','uk.youtube.com'] and document.has_key('embed') and document['embed']:
                        content += ' <h4 align="left">'+timeString+'</h4>'
                        if document.has_key('page_title') and document['page_title']:
                            content += '<p>'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                        else:
                            content += '<p>'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['url']+'</a>'+self.insert_parent_hyperlink(document)
                        #endif
                        content += '</p>'
                        count += 1
                    elif document.has_key('page_title') and document['page_title']:
                        content += ' <h4 align="left">'+timeString+'</h4>'
                        content += '<p><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a></p>'
                        count += 1
                    #endif
                #endif
                if count >= 32:
                    break;
                #endif
            #endfor
            if count >= 32:
                break;
            #endif
        #endfor
        return content
    #enddef

    @cherrypy.expose
    def how_you_can_help(self):
        epoch = int(time.time())
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, follow')
        
        content += '<h2>How You Can Help</h2>'
        
        content += '<div id="introduction">'
        
        content += '<h3 class="introduction">Submit a URL</h3>'
        
        content += '<p class="introduction">Should you come across a URL that you believe we have not scanned yet, please feel free to submit it to us just in case it is not on the backlog waiting to be processed. Should you create a brand new RISC OS-related web site, please feel free to submit its home page and we will spider our way to the rest.</p>'
        
        content += '<h3 class="introduction">ZIP File Format</h3>'
        
        content += '<p class="introduction">Should you host legacy .zip files on your own website, ensure that they have been resaved in the more modern .zip file format.</p>'
        
        content += '<h3 class="introduction">Hosting a riscos.xml File On Your Own Web Site</h3>'
        
        content += '<p class="introduction">Should you host your own web site, we would appreciate being able to obtain details about your RISC OS software, etc. by reading your very own riscos.xml file hosted on such web site.</p>'
        
        content += '<h3 class="introduction">Quarantine/Blacklist</h3>'
        
        content += '<p class="introduction">Report to us any RISC OS-related web site you would rather we did not catalogue and the reason why.</p>'
        
        content += '<h3 class="introduction">Rescanning</h3>'
        
        content += '<p class="introduction">Should you discover an out-of-date or incorrect record, please feel free to click on its "Rescan" button (if present) to force the record itself to be deleted but for its related URL to be scheduled for a rescan sometime in the near future. Note that a record has to be at or over a certain age for its "Rescan" button to appear.</p>'
        
        content += '<h3 class="introduction">Source Code</h3>'
        
        content += '<p class="introduction">We always welcome constructive comments on how either the web site or the spidering algorithm can be enhanced. Any advice you can offer on how we can extract even more useful information out of RISC OS Software will be much appreciated.</p>'
        
        content += '<h3 class="introduction">Mirror Hosting</h3>'
        
        content += '<p class="introduction">A single instance of The RISC OS Search Engine web site could be, at times, under an enormous load not to mention the effect on "The RISC OS Community" should it go down for whatever reason.</p>'
        
        content += '<p class="introduction">You can assist us by hosting a mirror of The RISC OS Search Engine web site on your own web server.</p>'
        
        content += '<p class="introduction">Requirements of The RISC OS Search Engine web site:'
        content += '<ul><li>Windows or Linux computer</li><li>Python 2.7x</li><li>CherryPy (Python-based web framework)</li><li>MongoDB  (NoSQL database management system)</li><li>pymongo (Python-based library for MongoDB)</li></ul></p>'
        
        content += '<h3 class="introduction">Spidering</h3>'
        
        content += '<p class="introduction">A single instance of The RISC OS Search Engine spidering program can not possibly cope with spidering all the RISC OS web sites throughout the entire Internet in a timely fashion.</p>'
        
        content += '<p class="introduction">You can assist us by joining in with the enormous task of spidering the Internet.</p>'
        
        content += '<p class="introduction">Requirements of The RISC OS Search Engine spidering program:'
        content += '<ul><li>Windows or Linux computer</li><li>Python 2.7x</li><li>MongoDB  (NoSQL database management system)</li><li>pymongo (Python-based library for MongoDB)</li><li>lxml (Python library for XML)</li></ul></p>'
        
        content += '<p class="introduction">Please don\'t hesitate to <a href="mail:rebecca.shalfield@shalfield.com">Contact Us</a> if you are interested in either hosting a mirror of The RISC OS Search Engine web site or assisting with the spidering.</p>'

        content += '</div>'
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def introduction(self):
        epoch = int(time.time())
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, follow')
        content += '<h2>Introduction</h2>'
        content += '<div id="introduction">'
        content += '<table border="0"><tr><td align="center" valign="middle"><img src="/riscos/images/AcornLogo.png"></td><td rowspan="2" valign="top">'
        content += '<p class="introduction">Welcome to The RISC OS Search Engine, a completely automated web site primarily dedicated to finding and cataloguing software for and collating data via the <a href="/riscos/riscos_distributed_information_model">RISC OS Distributed Information Model</a> about the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers.</p>'
        content += '<p class="introduction">During the development of the RISC OS Search Engine, our aim was never to try and replace main stream search engines such as Google or Bing.</p>'
        content += '<p class="introduction">As you read this, our Search Engine is spidering around the World Wide Web basically looking for RISC OS-related web sites containing .zip files. Upon finding such a file, its contents will be analysed and information about the RISC OS Software it contains will be extracted and stored in our Database. Along the way, we also search for and collate the contents of riscos.xml files, capture the title of each HTML page and make a note of any Spark or Arc files we encounter.</p>'
        content += '<p class="introduction">For RISC OS users without a suitable decompression application to unpack archive files, SparkPlug is available as a <a href="http://www.davidpilling.net/splug.bas">self-extracting archive</a>. Once downloaded, just set its filetype to \'BASIC\' and double-click on it to create the !SparkPlug application.</p>'
        content += '<p class="introduction">It should be noted that not all RISC OS Software will be found via The RISC OS Search Engine as we may be prevented from indexing a zip file due to settings in robots.txt and any knowledge we have of commercial RISC OS Software comes to us by way of riscos.xml files so we\'re completely at the mercy of the developers!</p>'
        content += '<p class="introduction">The RISC OS Search Engine is being developed by Rebecca Shalfield for "The RISC OS Community" and as a partner for the <a href="http://www.riscpkg.org">RISC OS Packaging Project</a> (<a href="http://www.plingstore.org.uk">!Store</a>, <a href="https://sites.google.com/site/alansriscosstuff/packman">!PackMan</a> and <a href="http://www.riscpkg.org/riscpkg.xhtml">!RiscPkg</a>).</p>'
        content += '<p class="introduction">Disclaimer: As we are currently unable to completely identify whether RISC OS Software downloadable via this web site will actually run on your particular version of RISC OS, the downloading and installation of any such Software is entirely at your own risk!</p>'
        content += '<p class="introduction">The RISC OS Search Engine is primarily collating links to external web sites and RISC OS Software. No RISC OS Software is directly downloadable from the computer hosting The RISC OS Search Engine except that explicitly added by an individual hosting a mirror, such as the products of Cherisha Software.</p>'
        content += '<p class="introduction">The benefits of the <a href="/riscos/riscos_distributed_information_model">RISC OS Distributed Information Model</a> to RISC OS authors, developers and service providers is that it is they themselves that are in complete control. They have the power to add, update or remove any of their own records as and when they see fit and they get free advertising into the bargain!</p>'
        
        content += '<p class="introduction">The development of an XML-based RISC OS Distributed Information Model has been the subject of several forum discussions stretching back over the last decade:<ul>'
        content += '<li><a href="http://www.drobe.co.uk/riscos/artifact1064.html" target="_new">2004-05-21</a></li>'
        content += '<li><a href="http://nutshells.anjackson.net/node/804" target="_new">2004-09-17</a></li>'
        content += '<li><a href="http://www.drobe.co.uk/riscos/artifact1410.html" target="_new">2005-08-02</a></li>'
        content += '<li><a href="http://www.iconbar.com/forums/viewthread.php?threadid=9659&page=2#comments" target="_new">2005-12-04</a></li>'
        content += '<li><a href="http://www.iconbar.com/forums/viewthread.php?threadid=7932" target="_new">2006-09-14</a></li>'
        content += '<li><a href="http://newsgroups.derkeiler.com/Archive/Comp/comp.sys.acorn.announce/2007-01/msg00020.html" target="_new">2007-01-28</a></li>'
        content += '<li><a href="http://www.drobe.co.uk/reply.php?id=522696" target="_new">2007-06-23</a></li>'
        content += '<li><a href="http://www.mofeel.net/620-comp-sys-acorn-announce/320.aspx" target="_new">2007-12-15</a></li>'
        content += '</ul></p>'
        
        content += '<p class="introduction">Although much has been achieved and many problems overcome, the RISC OS Search Engine is far from complete. Future directions might be in one or more of the following:<ul>'
        content += '<li>Encourage developers and/or enthusiasts to take the RISC OS Markup Language to their hearts.</li>'
        content += '<li>Encourage RISC OS Open Limited to adopt the RISC OS Markup Language.</li>'
        content += '<li>Better integration with !Store.</li>'
        content += '<li>Better integration with !PackMan.</li>'
        content += '<li>Integration with !StrongHelp.</li>'
        content += '<li>Development of a RISC OS application or relocatable module to allow direct searching.</li>'
        content += '<li>Generation of a PDF-based RISC OS Software Catalogue</li>'
        content += '</ul></p>'
        
        content += '<p class="introduction">As this web site\'s three Python source code files and the entire contents of our Database are being made freely available to "The RISC OS Community", please feel free to use in any way you wish for the good of "The RISC OS Community" just so long as you don\'t make a profit!</p>'
        content += '<p class="introduction">We actively encourage this RISC OS Search Engine web site in its entirety to be cloned and mirrored throughout the Internet. It is envisaged that this RISC OS Search Engine @ '+self.mirror+' will be just one of many, all sharing data between them!</p>'
        
        content += '<p class="introduction">We especially want the source code to the RISC OS Search Engine to form the basis of a number of other RISC OS-related web sites developed by others but concentrating on a specific section of the information in riscos.xml files but presented in a totally different way!</p>'
        
        try:
            # Returns all riscos plus rejects documents scanned in the last 28 days
            riscosCount = self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-2419200}}).count()
            rejectsCount = self.rejectsCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-2419200}}).count()
            reservesCount = self.reservesCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-2419200}}).count()
            urlsCount = self.urlsCollection.find({'url':{'$ne':['']}}).count()
            content += '<p class="introduction">We are averaging '+str(int((riscosCount+rejectsCount)/28))+' URL scans a day; it will therefore take us '+str(int(urlsCount/((riscosCount+rejectsCount+reservesCount)/28)))+' days to plough through the backlog!</p>'
        except:
            True
        
        timeSourceLastModified = time.ctime(os.stat(self.path+os.sep+'riscos.py')[8])
        content += '<p class="introduction">This web site is undergoing regular development as at '+str(timeSourceLastModified)+'.</p>'
        
        content += '<p class="introduction">Contributions to this web site or suggestions for improvement are always welcome.</p>'
        content += '<p class="introduction">The RISC OS Search Engine is written in Python and utilises lxml, CherryPy, MongoDB and JQuery.</p>'
        content += '<p><img src="/riscos/images/HTML5_Logo_32.png"> <img src="/riscos/images/python-powered-w-70x28.png"> <img src="/riscos/images/cherrypy.jpg"> <img src="/riscos/images/PoweredMongoDBgreen50.png"></p>'
        content += '</td><td align="center" valign="middle"><a href="https://www.riscosopen.org/content/" target="_blank"><img src="/riscos/images/RiscOsPiLogo.png" border="0"></a></td></tr>'
        
        content += '<tr><td align="center" valign="middle"><img src="/riscos/images/AcornArchimedes.png"></td><td align="center" valign="middle"><a href="http://www.raspberrypi.org/" target="_blank"><img src="/riscos/images/RaspberryPi.jpg" border="0"></a></td></tr>'
        
        content += '</table>'
        content += '</div>'
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def absolute(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Absolute Search</h2>'
        
        if not search:
            distinctAbsolutes = self.riscosCollection.find({"absolutes":{"$exists":True,"$ne":""}}).distinct("absolutes")
            content += '<h3>We currently know about '+str(len(distinctAbsolutes))+' distinct absolutes!</h3>'
        #endif
        
        content += '<p><form action="/riscos/absolute" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchabsolute" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchabsolute" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['absolutes']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
            
        #endif
        content += self.footer()
        return content
    #enddef    
    
    @cherrypy.expose
    def app(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Application Search</h2>'
        
        if not search:
            distinctApps = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""}}).distinct("directory")
            content += '<h3>We currently know about '+str(len(distinctApps))+' distinct applications!</h3>'
        #endif
        
        content += '<p><form action="/riscos/app" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchapp" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchapp" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("directory")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['application_name','directory']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def filetype(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Filetype Search</h2>'
        
        if not search:
            distinctFiletypes = self.riscosCollection.find({"filetypes_set":{"$exists":True,"$ne":""}}).distinct("filetypes_set")
            content += '<h3>We currently know about '+str(len(distinctFiletypes))+' distinct filetypes!</h3>'
        #endif
        
        content += '<p><form action="/riscos/filetype" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchfiletype" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchfiletype" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['filetypes_set','filetypes_run']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += '<p><form class="inline" action="/riscos/filetypes" method="post"><input class="button" type="submit" value="Filetypes"></form></p>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def font(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Font Search</h2>'
        
        if not search:
            distinctFonts = self.riscosCollection.find({"fonts":{"$exists":True,"$ne":""}}).distinct("fonts")
            content += '<h3>We currently know about '+str(len(distinctFonts))+' distinct fonts!</h3>'
        #endif
        
        content += '<p><form action="/riscos/font" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchfont" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchfont" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['fonts']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def computer(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Computer Search</h2>'
        
        if not search:
            distinctComputers = self.riscosCollection.find({"computer":{"$exists":True,"$ne":""}}).distinct("computer")
            content += '<h3>We currently know about '+str(len(distinctComputers))+' distinct computers!</h3>'
        #endif
        
        content += '<p><form action="/riscos/computer" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchcomputer" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchcomputer" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("computer")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['computer']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef    
    
    @cherrypy.expose
    def peripheral(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Peripheral Search</h2>'
        
        if not search:
            distinctPeripherals = self.riscosCollection.find({"peripheral":{"$exists":True,"$ne":""}}).distinct("peripheral")
            content += '<h3>We currently know about '+str(len(distinctPeripherals))+' distinct peripherals!</h3>'
        #endif
        
        content += '<p><form action="/riscos/peripheral" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchperipheral" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchperipheral" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("peripheral")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['peripheral']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef  
    
    @cherrypy.expose
    def podule(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Podule Search</h2>'
        
        if not search:
            distinctPodules = self.riscosCollection.find({"podule":{"$exists":True,"$ne":""}}).distinct("podule")
            content += '<h3>We currently know about '+str(len(distinctPodules))+' distinct podules!</h3>'
        #endif
        
        content += '<p><form action="/riscos/podule" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchpodule" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchpodule" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("podule")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['podule']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef    
    
    @cherrypy.expose
    def book(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Book Search</h2>'
        
        if not search:
            distinctBooks = self.riscosCollection.find({"book":{"$exists":True,"$ne":""}}).distinct("book")
            content += '<h3>We currently know about '+str(len(distinctBooks))+' distinct books!</h3>'
        #endif
        
        content += '<p><form action="/riscos/book" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchbook" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchbook" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("book")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['book']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef      
    
    @cherrypy.expose
    def magazine(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Magazine Search</h2>'
        
        if not search:
            distinctMagazines = self.riscosCollection.find({"magazine":{"$exists":True,"$ne":""}}).distinct("magazine")
            content += '<h3>We currently know about '+str(len(distinctMagazines))+' distinct magazines!</h3>'
        #endif
        
        content += '<p><form action="/riscos/magazine" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchmagazine" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchmagazine" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("magazine")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['magazine']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef    
    
    @cherrypy.expose
    def project(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Project Search</h2>'
        
        if not search:
            distinctProjects = self.riscosCollection.find({"project":{"$exists":True,"$ne":""}}).distinct("project")
            content += '<h3>We currently know about '+str(len(distinctProjects))+' distinct projects!</h3>'
        #endif
        
        content += '<p><form action="/riscos/project" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchproject" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchproject" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("project")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['project']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def event(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Event Search</h2>'
        
        if not search:
            distinctEvents = self.riscosCollection.find({"event":{"$exists":True,"$ne":""}}).distinct("event")
            content += '<h3>We currently know about '+str(len(distinctEvents))+' distinct events!</h3>'
        #endif
        
        content += '<p><form action="/riscos/event" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchevent" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchevent" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("event")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['event']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def video(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Video Search</h2>'
        
        if not search:
            distinctVideos = self.riscosCollection.find({"video":{"$exists":True,"$ne":""}}).distinct("video")
            content += '<h3>We currently know about '+str(len(distinctVideos))+' distinct videos!</h3>'
        #endif
        
        content += '<p><form action="/riscos/video" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchvideo" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchvideo" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['video']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def dealer(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Dealer Search</h2>'
        
        if not search:
            distinctDealers = self.riscosCollection.find({"dealer":{"$exists":True,"$ne":""}}).distinct("dealer")
            content += '<h3>We currently know about '+str(len(distinctDealers))+' distinct dealers!</h3>'
        #endif
        
        content += '<p><form action="/riscos/dealer" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchdealer" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchdealer" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("dealer")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['dealer']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def developer(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Developer Search</h2>'
        
        if not search:
            distinctDevelopers = self.riscosCollection.find({"developer":{"$exists":True,"$ne":""}}).distinct("developer")
            content += '<h3>We currently know about '+str(len(distinctDevelopers))+' distinct developers!</h3>'
        #endif
        
        content += '<p><form action="/riscos/developer" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchdeveloper" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchdeveloper" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'
        
        if not search:
            content += self.insert_advert("developer")
        #endif

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['developer']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def forum(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Forum Search</h2>'
        
        if not search:
            distinctForums = self.riscosCollection.find({"forum":{"$exists":True,"$ne":""}}).distinct("forum")
            content += '<h3>We currently know about '+str(len(distinctForums))+' distinct forums!</h3>'
        #endif
        
        content += '<p><form action="/riscos/forum" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchforum" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchforum" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("forum")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['forum']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def errormessage(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Error Message Search</h2>'
        
        if not search:
            distinctErrorMessages = self.riscosCollection.find({"error_message":{"$exists":True,"$ne":""}}).distinct("error_message")
            content += '<h3>We currently know about '+str(len(distinctErrorMessages))+' distinct error messages!</h3>'
        #endif
        
        content += '<p><form action="/riscos/errormessage" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searcherrormessage" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searcherrormessage" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            errorMessages = []
            attributesToSearch = ['error_message']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    errorMessages += self.riscosCollection.find(searchCriteria).distinct('error_message')
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            content += self.display_errormessage_entries(errorMessages)
        #endif
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def faq(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>FAQ Search</h2>'
        
        if not search:
            distinctFAQs = self.riscosCollection.find({"question":{"$exists":True,"$ne":""}}).distinct("question")
            content += '<h3>We currently know about '+str(len(distinctFAQs))+' distinct FAQs!</h3>'
        #endif
        
        content += '<p><form action="/riscos/faq" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchfaq" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchfaq" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            questions = []
            attributesToSearch = ['question']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    questions += self.riscosCollection.find(searchCriteria).distinct('question')
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            content += self.display_faq_entries(questions)
        #endif
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def howto(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>How-To Search</h2>'
        
        if not search:
            distinctHowTos = self.riscosCollection.find({"howto":{"$exists":True,"$ne":""}}).distinct("howto")
            content += '<h3>We currently know about '+str(len(distinctHowTos))+' distinct how-tos!</h3>'
        #endif
        
        content += '<p><form action="/riscos/howto" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchhowto" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchhowto" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            howTos = []
            attributesToSearch = ['howto']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    howTos += self.riscosCollection.find(searchCriteria).distinct('howto')
                    howTos = list(set(howTos))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif

            content += '<div id="introduction">'
            content += '<dl>'
            for howTo in howTos:
                for document in self.riscosCollection.find({'howto':howTo}):
                    if document.has_key('description') and document['description']:
                        content += '<dt>'+document['howto']+'</dt>'
                        content += '<dd><p>'+document['description']+'</p>'
                        if document.has_key('image_url') and document['image_url']:
                            content += '<img src="'+document['image_url']+'"'
                            if document.has_key('image_caption') and document['image_caption']:
                                content += ' alt="'+document['image_caption']+'"'
                            #endif
                            content += '>'
                        #endif
                        content += '<p class="housekeeping"><a href="'+document['parent_url']+'"  title="'+document['parent_url']+'">Source</a></p>'
                        content += '</dd>'
                    #endif
                #endfor
            #endfor
            content += '</dl></div>' 

        #endif
        content += self.footer()
        return content
    #enddef        
    
    @cherrypy.expose
    def glossary(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Glossary Term Search</h2>'
        
        if not search:
            distinctGlossaryTerms = self.riscosCollection.find({"glossary_term":{"$exists":True,"$ne":""}}).distinct("glossary_term")
            content += '<h3>We currently know about '+str(len(distinctGlossaryTerms))+' distinct glossary terms!</h3>'
        #endif
        
        content += '<p><form action="/riscos/glossary" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchglossary" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchglossary" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            terms = []
            attributesToSearch = ['glossary_term']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    terms += self.riscosCollection.find(searchCriteria).distinct('glossary_term')
                    terms = list(set(terms))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            content += self.display_glossary_entries(terms)
        #endif
        content += self.footer()
        return content
    #enddef

    def display_glossary_entries(self, terms):
        content = ""
        content += '<div id="introduction">'
        content += '<dl>'
        terms.sort()
        for term in terms:
            for document in self.riscosCollection.find({'glossary_term':term}):
                if document.has_key('glossary_definition') and document['glossary_definition']:
                    content += '<dt>'+document['glossary_term']+'</dt>'
                    content += '<dd>'+document['glossary_definition']+' <sup><small><a href="'+document['parent_url']+'"  title="'+document['parent_url']+'">Source</a></small></sup>'
                    if document.has_key('image_url') and document['image_url']:
                        content += '<img src="'+document['image_url']+'"'
                        if document.has_key('image_caption') and document['image_caption']:
                            content += ' alt="'+document['image_caption']+'"'
                        #endif
                        content += '>'
                    #endif
                    content += '</dd>'
                #endif
            #endfor
        #endfor
        content += '</dl></div>'       
        return content
    #enddef
    
    def display_faq_entries(self, questions):
        content = ""
        content += '<div id="introduction">'
        content += '<dl>'
        questions.sort()
        for question in questions:
            for document in self.riscosCollection.find({'question':question}):
                if document.has_key('answer') and document['answer']:
                    content += '<dt>'+document['question']+'</dt>'
                    content += '<dd>'+document['answer']+' <sup><small><a href="'+document['parent_url']+'"  title="'+document['parent_url']+'">Source</a></small></sup>'
                    if document.has_key('image_url') and document['image_url']:
                        content += '<img src="'+document['image_url']+'">'
                    #endif
                    content += '</dd>'
                #endif
            #endfor
        #endfor
        content += '</dl></div>'       
        return content
    #enddef
    
    def display_errormessage_entries(self, errormessages):
        content = ""
        content += '<div id="introduction">'
        content += '<dl>'
        errormessages.sort()
        for errormessage in errormessages:
            for document in self.riscosCollection.find({'error_message':errormessage}):
                if (document.has_key('cause') and document['cause']) or (document.has_key('solution') and document['solution']):
                    content += '<dt>'+document['error_message']+'</dt>'
                    content += '<dd>'
                    if document.has_key('cause') and document['cause']:
                        content += '<p><b>Cause: </b>'+document['cause']+'</p>'
                    #endif
                    if document.has_key('solution') and document['solution']:
                        content += '<p><b>Solution: </b>'+document['solution']+'</p>'
                    #endif
                    content += '<p align="right"><sup><small><a href="'+document['parent_url']+'"  title="'+document['parent_url']+'">Source</a></small></sup></p>'
                    content += '</dd>'
                #endif
            #endfor
        #endfor
        content += '</dl></div>'       
        return content
    #enddef
    
    @cherrypy.expose
    def categorisation(self, primary="", secondary="", tertiary=""):
        status = self.cookie_handling()
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content = ""
        content += self.header(status, 'index, follow')
        content += '<h2>Categorisation</h2>'
        content += '<div id="introduction">'
        if primary and secondary and tertiary:
            content += '<h3><form class="inline" action="/riscos/categorisation?primary='+primary+'" method="post"><input class="button" type="submit" value="'+primary+'"></form> &rArr; <form class="inline" action="/riscos/categorisation?primary='+primary+'&secondary='+secondary+'" method="post"><input class="button" type="submit" value="'+secondary+'"></form> &rArr; '+tertiary+'</h3>'
            for taxonomyEntry in self.taxonomy:
                catPrimary = ""
                catSecondary = ""
                catTertiary = ""
                catRegex = ""
                if len(taxonomyEntry) == 4:
                    [catPrimary,catSecondary,catTertiary,catRegex] = taxonomyEntry
                    if catPrimary == primary and catSecondary == secondary and catTertiary == tertiary:
                        searchCriteria = {}
                        searchCriteria['help'] = re.compile(catRegex)
                        doc_ids = self.riscosCollection.find(searchCriteria).distinct('_id')
                        filteredDocIds = self.apply_filter(userDocument, doc_ids)
                        if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                            content += self.display_document_table(filteredDocIds, 'categorisation', False)
                        else:
                            content += self.display_document_report(filteredDocIds, 'categorisation', False)
                        #endif
                        break
                    #endif
                #endif
            #endfor
        elif primary and secondary:
            content += '<h3><form class="inline" action="/riscos/categorisation?primary='+primary+'" method="post"><input class="button" type="submit" value="'+primary+'"></form> &rArr; '+secondary+'</h3>'
            distinctValues = []
            catPrimaries = []
            catSecondaries = []
            catTertiaries = []
            catRegexes = []
            for taxonomyEntry in self.taxonomy:
                distinctValue = ""
                if len(taxonomyEntry) == 4:
                    [catPrimary,catSecondary,catTertiary,catRegex] = taxonomyEntry
                    if catPrimary == primary and catSecondary == secondary:                   
                        catTertiaries.append(catTertiary)
                    #endif
                elif len(taxonomyEntry) == 3:
                    [catPrimary,catSecondary,catRegex] = taxonomyEntry
                    if catPrimary == primary and catSecondary == secondary:                   
                        catRegexes.append(catRegex)
                    #endif
                #endif
            #endfor            
            if catTertiaries:
                for taxonomyEntry in self.taxonomy:
                    catPrimary = ""
                    catSecondary = ""
                    catTertiary = ""
                    catRegex = ""
                    distinctValue = ""
                    if len(taxonomyEntry) == 4:
                        [catPrimary,catSecondary,catTertiary,catRegex] = taxonomyEntry
                        if catPrimary == primary and catSecondary == secondary:                   
                            distinctValue = '<tr><td align="left"><form class="inline" action="/riscos/categorisation?primary='+primary+'&secondary='+secondary+'&tertiary='+catTertiary+'" method="post"><input class="button" type="submit" value="'+catTertiary+'"></form></td></tr>'
                        #endif
                    elif len(taxonomyEntry) == 3:
                        [catPrimary,catSecondary,catRegex] = taxonomyEntry
                        if catPrimary == primary and catSecondary == secondary:                   
                            distinctValue = '<tr><td align="left">'+catRegex+'</td></tr>'
                        #endif
                    #endif
                    if distinctValue and not distinctValue in distinctValues:
                        distinctValues.append(distinctValue)
                    #endif 
                #endfor
                content += '<table border="0">'
                for distinctValue in distinctValues:
                    content += distinctValue
                #endfor
                content += '</table>'
            elif catRegexes:
                for taxonomyEntry in self.taxonomy:
                    catPrimary = ""
                    catSecondary = ""
                    catTertiary = ""
                    catRegex = ""
                    if len(taxonomyEntry) == 3:
                        [catPrimary,catSecondary,catRegex] = taxonomyEntry
                        if catPrimary == primary and catSecondary == secondary:
                            searchCriteria = {}
                            searchCriteria['help'] = re.compile(catRegex)
                            doc_ids = self.riscosCollection.find(searchCriteria).distinct('_id')
                            filteredDocIds = self.apply_filter(userDocument, doc_ids)
                            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                                content += self.display_document_table(filteredDocIds, 'categorisation', False)
                            else:
                                content += self.display_document_report(filteredDocIds, 'categorisation', False)
                            #endif
                            break
                        #endif
                    #endif
                #endfor
            #endif            
        elif primary:
            content += '<h3>'+primary+'</h3>'
            distinctValues = []
            catSecondaries = []
            catRegexes = []
            for taxonomyEntry in self.taxonomy:
                distinctValue = ""
                if len(taxonomyEntry) == 4:
                    [catPrimary,catSecondary,catTertiary,catRegex] = taxonomyEntry
                    if catPrimary == primary:                   
                        catSecondaries.append(catSecondary)
                    #endif
                elif len(taxonomyEntry) == 3:
                    [catPrimary,catSecondary,catRegex] = taxonomyEntry
                    if catPrimary == primary:                   
                        catSecondaries.append(catSecondary)
                    #endif                    
                elif len(taxonomyEntry) == 2:
                    [catPrimary,catRegex] = taxonomyEntry
                    if catPrimary == primary:                   
                        catRegexes.append(catRegex)
                    #endif
                #endif
            #endfor          
            if catSecondaries:
                for taxonomyEntry in self.taxonomy:
                    catPrimary = ""
                    catSecondary = ""
                    catTertiary = ""
                    catRegex = ""
                    distinctValue = ""
                    if len(taxonomyEntry) == 4:
                        [catPrimary,catSecondary,catTertiary,catRegex] = taxonomyEntry
                        if catPrimary == primary:                   
                            distinctValue = '<tr><td align="left"><form class="inline" action="/riscos/categorisation?primary='+primary+'&secondary='+catSecondary+'" method="post"><input class="button" type="submit" value="'+catSecondary+'"></form></td></tr>'
                        #endif
                    elif len(taxonomyEntry) == 3:
                        [catPrimary,catSecondary,catRegex] = taxonomyEntry
                        if catPrimary == primary:                   
                            distinctValue = '<tr><td align="left"><form class="inline" action="/riscos/categorisation?primary='+primary+'&secondary='+catSecondary+'" method="post"><input class="button" type="submit" value="'+catSecondary+'"></form></td></tr>'
                        #endif
                    #endif
                    if distinctValue and not distinctValue in distinctValues:
                        distinctValues.append(distinctValue)
                    #endif 
                #endfor
                content += '<table border="0">'
                for distinctValue in distinctValues:
                    content += distinctValue
                #endfor
                content += '</table>'
            elif catRegexes:
                for taxonomyEntry in self.taxonomy:
                    catPrimary = ""
                    catRegex = ""
                    if len(taxonomyEntry) == 2:
                        [catPrimary,catRegex] = taxonomyEntry
                        if catPrimary == primary:
                            searchCriteria = {}
                            searchCriteria['help'] = re.compile(catRegex)
                            doc_ids = self.riscosCollection.find(searchCriteria).distinct('_id')
                            filteredDocIds = self.apply_filter(userDocument, doc_ids)
                            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                                content += self.display_document_table(filteredDocIds, 'categorisation', False)
                            else:
                                content += self.display_document_report(filteredDocIds, 'categorisation', False)
                            #endif
                            break
                        #endif
                    #endif
                #endfor
            #endif
        else:
            distinctValues = []     
            for taxonomyEntry in self.taxonomy:
                if not taxonomyEntry[0] in distinctValues:
                    distinctValues.append(taxonomyEntry[0])
                #endif
            #endfor
            content += '<table border="0">'
            for distinctValue in distinctValues:
                content += '<tr><td align="left"><form class="inline" action="/riscos/categorisation?primary='+distinctValue+'" method="post"><input class="button" type="submit" value="'+distinctValue+'"></form></td></tr>'
            #endfor
            content += '</table>'
        #endif
        content += '</div>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def module(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif        

        content += '<h2>Relocatable Module Search</h2>'
        
        if not search:
            distinctModules = self.riscosCollection.find({"relocatable_modules.name":{"$exists":True,"$ne":""}}).distinct("relocatable_modules.name")
            content += '<h3>We currently know about '+str(len(distinctModules))+' distinct relocatable modules!</h3>'
        #endif
        
        content += '<p><form action="/riscos/module" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchmodule" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchmodule" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['relocatable_modules.name']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def monitor(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Monitor Definition File Search</h2>'
        
        if not search:
            distinctMdfs = self.riscosCollection.find({"monitor_definition_files":{"$exists":True,"$ne":""}}).distinct("monitor_definition_files")
            content += '<h3>We currently know about '+str(len(distinctMdfs))+' distinct monitor definition files!</h3>'
        #endif
        
        content += '<p><form action="/riscos/monitor" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchmonitor" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchmonitor" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['monitor_definition_files']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def service(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Service Search</h2>'
        
        if not search:
            distinctProviders = self.riscosCollection.find({"provider":{"$exists":True,"$ne":""}}).distinct("provider")
            content += '<h3>We currently know about '+str(len(distinctProviders))+' distinct providers!</h3>'
        #endif
        
        content += '<p><form action="/riscos/service" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchservice" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchservice" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("provider")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['provider']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def softwareinterrupt(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>SoftWare Interrupt (SWI) Search</h2>'
        
        if not search:
            distinctSoftwareInterrupts = self.riscosCollection.find({"relocatable_modules.software_interrupts":{"$exists":True,"$ne":""}}).distinct("relocatable_modules.software_interrupts.name")
            content += '<h3>We currently know about '+str(len(distinctSoftwareInterrupts))+' distinct software interrupts!</h3>'
        #endif
        
        content += '<p><form action="/riscos/softwareinterrupt" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchsoftwareinterrupt" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchsoftwareinterrupt" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['relocatable_modules.software_interrupts.name']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def starcommand(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>* Command Search</h2>'
        
        if not search:
            distinctStarCommands = self.riscosCollection.find({"relocatable_modules.star_commands":{"$exists":True,"$ne":""}}).distinct("relocatable_modules.star_commands.name")
            content += '<h3>We currently know about '+str(len(distinctStarCommands))+' distinct * commands!</h3>'
        #endif
        
        content += '<p><form action="/riscos/starcommand" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchstarcommand" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchstarcommand" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['relocatable_modules.star_commands.name']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def usergroup(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>User Group Search</h2>'
        
        if not search:
            distinctUserGroups = self.riscosCollection.find({"user_group":{"$exists":True,"$ne":""}}).distinct("user_group")
            content += '<h3>We currently know about '+str(len(distinctUserGroups))+' distinct user groups!</h3>'
        #endif
        
        content += '<p><form action="/riscos/usergroup" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchusergroup" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchusergroup" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if not search:
            content += self.insert_advert("user_group")
        #endif
        
        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['user_group']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef 
    
    @cherrypy.expose
    def utility(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif      

        content += '<h2>Utility Search</h2>'
        
        if not search:
            distinctUtilities = self.riscosCollection.find({"utilities.name":{"$exists":True,"$ne":""}}).distinct("utilities.name")
            content += '<h3>We currently know about '+str(len(distinctUtilities))+' distinct utilities!</h3>'
        #endif
        
        content += '<p><form action="/riscos/utility" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchutility" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchutility" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['utilities.name']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def printer(self, format="string", search=""):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['watchlist'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Printer Definition File Search</h2>'
        
        if not search:
            distinctPdfs = self.riscosCollection.find({"printer_definition_files":{"$exists":True,"$ne":""}}).distinct("printer_definition_files")
            content += '<h3>We currently know about '+str(len(distinctPdfs))+' distinct printer definition files!</h3>'
        #endif
        
        content += '<p><form action="/riscos/printer" method="post">'
        content += '<select name="format">'
        for potentialFormat in ['string','regex']:
            if potentialFormat == format:
                content += '<option value="'+potentialFormat+'" selected>'+potentialFormat.capitalize()+'</option>'
            else:
                content += '<option value="'+potentialFormat+'">'+potentialFormat.capitalize()+'</option>'
            #endif
        #endfor
        content += '</select> '
        if search:
            content += '<input id="searchprinter" type="text" size="40" name="search" value="'+search+'">'
        else:
            content += '<input id="searchprinter" type="text" size="40" name="search">'
        #endif
        content += '<input class="button" type="submit" value="Search">'
        content += '</form></p>'

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['printer_definition_files']
            for attributeToSearch in attributesToSearch:
                searchCriteria = {}
                try:
                    searchCriteria[attributeToSearch] = re.compile('(?i)'+search)
                    doc_ids += self.riscosCollection.find(searchCriteria).distinct('_id')
                    doc_ids = list(set(doc_ids))
                except:
                    content += "<h3 class=\"error\">Unlike Google, The RISC OS Search Engine uses Regular Expressions<br>Unfortunately, there is an error in `"+search+"`!"
                    for charToBeEscaped in ['\\','(',')','$','.','+']:
                        if charToBeEscaped in search and not '\\'+charToBeEscaped in search:
                            content += "<br>Try escaping `"+charToBeEscaped+"` with `\\"+charToBeEscaped+"` as in `"+search.replace(charToBeEscaped,'\\'+charToBeEscaped)+"`"
                        #endif
                    #endfor
                    content += "</h3>"
                    content += self.regex_table()
                    content += self.footer()
                    return content
                #endfor
            #endif
            
            filteredDocIds = self.apply_filter(userDocument, doc_ids)

            if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(filteredDocIds, 'generic_search', False)
            else:
                content += self.display_document_report(filteredDocIds, 'generic_search', False)
            #endif
            
            if len(filteredDocIds) == 1:
                content += self.display_dictionary_as_xml_and_json(filteredDocIds[0])
            #endif
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def key(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, follow')
        content += '<h2>Key</h2>'
        content += '<div id="key">'
        content += '<p class="key">'
        for (externalAttribute,internalAttribute,key) in self.searchableAttributes:
            content += '<b>'+externalAttribute+'</b> : '+key+'<br>'
        #endfor            
        content += '</p>'       
        content += '</div>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def quarantine(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'noindex, nofollow')
        content += '<h2>Quarantine</h2>'
        count = self.quarantineCollection.find().count()
        if count:
            if count == 1:
                content += '<p>Currently, there is '+str(count)+' record in quarantine!</p>'
            else:
                content += '<p>Currently, there are '+str(count)+' records in quarantine!</p>'
            #endif
            
            #domains = self.quarantineCollection.find({'domain':{'$exists':True,'$ne':""}}).distinct('domain')
            #if domains:
            #    domains.sort()
            #    content += '<p>Affected domains are as follows:</p><ul>'
            #    for domain in domains:
            #        content += '<li>'+domain+'</li>'
            #    #endfor
            #    content += '</ul>'
            ##endif
            
        else:
            content += '<p>Currently, there are no records in quarantine!</p>'
        #endif
        content += self.footer()
        return content
    #enddef    
        
    @cherrypy.expose
    def riscos_distributed_information_model(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, nofollow')
        content += '<h2>The RISC OS Distributed Information Model (RODIM)</h2>'
        content += '<div id="introduction">'
        content += '<p class="introduction">The RISC OS Distributed Information Model (RODIM) is an XML-based distributed information framework designed specifically for "The RISC OS Community". The RISC OS Distributed Information Model utilises riscos.xml files using the <a href="/riscos/riscos_markup_language">RISC OS Markup Language (ROML)</a>.</p>'
        content += '<p class="introduction">As a number of schemes similar to this one have been suggested and partially implemented over the years, we all need to do our bit to ensure that this time we succeed. Potential reasons for failure are:<ul>'
        content += '<li>RISC OS Markup Language seen as too-complicated.</li>'
        content += '<li>Lack of adoption of the RISC OS Markup Language.</li>'
        content += '<li>Lack of cooperation between the various RISC OS-related portal sites.</li>'
        content += '<li>Lack of interest from developers and/or enthusiasts.</li>'
        content += "<li>Rejection due to 'Not Invented Here'.</li>"
        content += '<li>Failure to deal with Denial of Service attacks.</li>'
        content += '</ul></p>'
        
        content += '<p class="introduction">The RISC OS Search Engine fully supports the RISC OS Distributed Information Model and RISC OS Markup Language.</p>'
        content += '<p class="introduction">Everyone in the RISC OS Community with a web site, be they a developer, dealer or simply an enthusiast, has the right to add a riscos.xml file to their very own web site.</p>'
        
        content += '<p class="introduction">The location of the riscos.xml file on your web site can either be in the same directory as robots.txt or in the same directory as a RISC OS-related page we would normally index and, of course, you can have as many riscos.xml files on your web site as you wish:<br>'
        content += '<ul>'
        content += '<li>http://www.yourdomain.com/riscos.xml</li>'
        content += '<li>http://www.yourdomain.com/robots.txt</li>'
        content += '</ul><br>'
        content += '<ul>'
        content += '<li>http://www.yourdomain.com/dir1/dir2/dirn/index.html</li>'
        content += '<li>http://www.yourdomain.com/dir1/dir2/dirn/riscos.xml</li>'
        content += '</ul>'
        content += '</p>'
        
        content += '<p class="introduction">Whenever the RISC OS Search Engine comes across a riscos.xml file, either as a result of spidering or having its URL submitted to us, it will be parsed and its contents added to our database.</p>'
        
        content += '<p class="introduction">Although the RISC OS Search Engine will automatically rescan your riscos.xml file every month, its URL can be submitted to us at any time to provide more frequent updates.</p>'
        
        content += '<p class="introduction">To remove a riscos.xml-originated record from our database, simply remove an individual record from your riscos.xml file and ask us to rescan it or remove the entire riscos.xml file from your web site altogether. Within 28 days, your records will have been updated.</p>'
        
        content += '<p><form class="inline" action="/riscos/riscos_xml_urls" method="post"><input class="button" type="submit" value="riscos.xml URLs"></form></p>'
        
        content += '</div>'
        content += self.footer()
        return content
    #enddef    
    
    @cherrypy.expose
    def riscos_markup_language(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, nofollow')
        content += '<h2>The RISC OS Markup Language (ROML)</h2>'
        content += '<div id="introduction">'
        content += '<p class="introduction">The RISC OS Markup Language is an entity in its own right, completely independent of the RISC OS Search Engine and any other RISC OS-related web site. Although the RISC OS Search Engine utilises the RISC OS Markup Language, it should not be considered a part of it.</p>'
        content += '<p class="introduction">The RISC OS Markup Language has yet to be adopted by RISC OS Open Limited.</p>'
        roml = '''
<?xml version="1.0" encoding="ISO-8859-1"?>
<?xml-stylesheet type="text/xsl" href="http://''' + self.mirror + '''/riscos.xsl"?>
<riscos version="0.99">
    <absolutes>
        <absolute>
            <name>?</name>
            <url>?</url>
        </absolute>
        ...
    </absolutes>
    <anniversaries>
       <anniversary>
            <date day="?" month="?" year="?"/>
            <description territory="?">?</description>
            <title>?</title>
            <url>?</url>
       </anniversary>
    </anniversaries>
    <apps>
        <app>
            <absolutes>
                <absolute>
                    <name>?</name>
                </absolute>
                ...
            </absolutes>
            <addressingMode>26-bit|32-bit|26/32-bit</addressingMode>
            <advertUrl>?</advertUrl>                
            <armArchitectures>
                <armv2/>
                <armv3/>
                <armv4/>
                <armv5/>
                <armv6/>
                <armv7/>
            </armArchitectures>
            <authors>
                <author>?</author>
                ...
            </authors>
            <copyright>?</copyright>
            <description territory="?">?</description>
            <developer>?</developer>
            <directory>?</directory>
            <filetypesRun>
                <filetypeRun>?</filetypeRun>
                ...
            </filetypesRun>
            <filetypesSet>
                <filetypeSet>?</filetypeSet>
                ...
            </filetypesSet>
            <fonts>
                <font>
                    <name>?</name>
                </font>
                ...
            </fonts>
            <iconUrl>?</iconUrl>
            <identifier>?</identifier>
            <image url="?" caption="?" />
            <keyStages>
                <keyStage>?</keyStage>
                ...
            </keyStages>
            <licence>?</licence>
            <maintainer>?</maintainer>
            <moduleDependencies>
                <moduleDependency>
                    <name>?</name>
                    <version>?</version>                
                </moduleDependency>
                ...
            </moduleDependencies>
            <name>?</name>
            <pricing>
                <singleuser currency="?">?</singleuser>
                <sitelicence currency="?">?</sitelicence>
                <upgrade from="?" to="?" currency="?">?</upgrade>
            </pricing>
            <programmingLanguages>
                <programmingLanguage>?</programmingLanguage>
                ...
            </programmingLanguages>
            <purpose>?</purpose>
            <released day="?" month="?" year="?"/>
            <relocatableModules>
                <relocatableModule>
                    <name>?</name>
                    <softwareInterrupts>
                        <softwareInterrupt>
                            <use>?</use>
                            <name>?</name>
                            <hexNumber>?</hexNumber>
                        </softwareInterrupt>
                        ...
                    </softwareInterrupts>
                    <starCommands>
                        <starCommand>
                            <use>?</use>
                            <name>?</name>
                        </starCommand>
                        ...
                    </starCommands> 
                    <version>?</version>               
                </relocatableModule>
                ...
            </relocatableModules>
            <systemVariables>
                <systemVariable>?</systemVariable>
                ...
            </systemVariables>
            <territories>
                <territory>?</territory>
                ...
            </territories>
            <url>?</url>
            <utilities>
                <utility>
                    <name>?</name>
                    <version>?</version>
                </utility>
                ...
            </utilities>                
            <version>?</version>
        </app>
        ...
    </apps>
    <books>
        <book>
            <advertUrl>?</advertUrl>
            <authors>
                <author>?</author>
                ...
            </authors>
            <description territory="?">?</description>
            <isbn>?</isbn>
            <image url="?" caption="?" />
            <pricing>
                <hardback currency="?">?</hardback>
                <softback currency="?">?</softback>
                <ebook currency="?">?</ebook>
            </pricing>
            <published day="?" month="?" year="?"/>
            <publisher>?</publisher>
            <territory>?</territory>
            <title>?</title>
            <url>?</url>
        </book>
        ...
    </books>
    <computers>
        <computer>
            <advertUrl>?</advertUrl>
            <developer>?</developer>
            <description territory="?">?</description>
            <identifier>?</identifier>
            <name>?</name>
            <pricing>
                <single currency="?">?</single>
            </pricing>
            <url>?</url>
        </computer>
        ...
    </computers>
    <dealers>
        <dealer>
            <address>?</address>
            <advertUrl>?</advertUrl>
            <contact>?</contact>
            <description territory="?">?</description>
            <email>?</email>
            <name>?</name>
            <telephone>?</telephone>
            <url>?</url>
        </dealer>
        ...
    </dealers>
    <developers>
        <developer>
            <address>?</address>
            <advertUrl>?</advertUrl>
            <contact>?</contact>
            <description territory="?">?</description>
            <email>?</email>
            <name>?</name>
            <telephone>?</telephone>
            <url>?</url>
        </developer>
        ...
    </developers>
    <errorMessages>
        <errorMessage>
            <message>?</message>
            <cause>?</cause>
            <solution>?</solution>
        </errorMessage>
        ...
    </errorMessages>
    <events>
        <event>
            <advertUrl>?</advertUrl>
            <date day="?" month="?" year="?"/>
            <description territory="?">?</description>
            <title territory="?">?</title>
            <url>?</url>
        </event>
        ...
    </events>
    <faqs>
        <faq>
            <question territory="?">?</question>
            <answer territory="?">?</answer>
            <image url="?" caption="?" />
            <sourceCode programmingLanguage="?">?</sourceCode>
        </faq>
    </faqs>
    <fonts>
        <font>
            <name>?</name>
            <url>?</url>
            <image url="?" caption="?" />
        </font>
        ...
    </fonts>    
    <forums>
       <forum>
           <advertUrl>?</advertUrl>
           <name>?</name>
           <description territory="?">?</description>
           <url>?</url>
       </forum>
       ...
    </forums>
    <glossary>
        <entry>
            <term>?</term>
            <definition territory="?">?</definition>
            <image url="?" caption="?" />
            <sourceCode programmingLanguage="?">?</sourceCode>
        </entry>
        ...
    </glossary>
    <howTos>
        <howTo>
            <task territory="?">?</task>
            <description territory="?">?</description>
            <image url="?" caption="?" />
            <sourceCode programmingLanguage="?">?</sourceCode>
        </howTo>
        ...
    </howTos>
    <magazines>
        <magazine>
            <advertUrl>?</advertUrl>
            <description territory="?">?</description>
            <issn>?</issn>
            <pricing>
                <issue currency="?">?</issue>
                <subscription currency="?" duration="?">?</subscription>
            </pricing>
            <publisher>?</publisher>
            <territory>?</territory>
            <title>?</title>
            <url>?</url>
        </magazine>
        ...
    </magazines>
    <monitorDefinitionFiles>
        <monitorDefinitionFile>
            <monitor>?</monitor>
            <url>?</url>
        </monitorDefinitionFile>
        ...
    </monitorDefinitionFiles>    
    <peripherals>
        <peripheral>
            <description territory="?">?</description>
            <developer>?</developer>
            <deviceType>?</deviceType>
            <identifier>?</identifier>
            <name>?</name>
            <url>?</url>
        </peripheral>
        ...
    </peripherals>
    <podules>
        <podule>
            <advertUrl>?</advertUrl>
            <description territory="?">?</description>
            <developer>?</developer>
            <identifier>?</identifier>
            <name>?</name>
            <pricing>
                <single currency="?">?</single>
            </pricing>
            <relocatableModules>
                <relocatableModule>
                    <name>?</name>
                    <softwareInterrupts>
                        <softwareInterrupt>
                            <use>?</use>
                            <name>?</name>
                            <hexNumber>?</hexNumber>
                        </softwareInterrupt>
                        ...
                    </softwareInterrupts>
                    <starCommands>
                        <starCommand>
                            <use>?</use>
                            <name>?</name>
                        </starCommand>
                        ...
                    </starCommands> 
                    <version>?</version>                
                </relocatableModule>
                ...
            </relocatableModules>
            <url>?</url>
        </podule>
        ...
    </podules>
    <printerDefinitionFiles>
        <printerDefinitionFile>
            <printer>?</printer>
            <url>?</url>
        </printerDefinitionFile>
        ...
    </printerDefinitionFiles>    
    <projects>
        <project>
            <name>?</name>
            <description territory="?">?</description>
            <url>?</url>
        </project>
    </projects>
    <relocatableModules>
        <relocatableModule>
            <addressingMode>26-bit|32-bit|26/32-bit</addressingMode>
            <name>?</name>
            <softwareInterrupts>
                <softwareInterrupt>
                    <use>?</use>
                    <interrupts>
                        <interrupt>?</interrupt>
                        ...
                    </interrupts>
                    <onEntry>
                        <register number="?" description="?" />
                        ...
                    </onEntry>
                    <onExit>
                        <register number="?" description="?" />
                        ...
                    </onExit>
                    <name reasonCode="?">?</name>
                    <hexNumber>?</hexNumber>
                    <processorMode>?</processorMode>
                    <reasonCode>?</reasonCode>
                    <relatedSwis>
                        <relatedSwi>?</relatedSwi>
                        ...
                    </relatedSwis>
                    <relatedVectors>
                        <relatedVector>?</relatedVector>
                        ...
                    </relatedVectors>
                    <reEntrancy>?</reEntrancy>
                    <summary>?</summary>
                </softwareInterrupt>
                ...
            </softwareInterrupts>
            <starCommands>
                <starCommand>
                    <example>?</example>
                    <name>?</name>
                    <parameters>
                        <parameter name="?" description="?" />
                        ...
                    </parameters>
                    <relatedCommands>
                        <relatedCommand>?</relatedCommand>
                        ...
                    </relatedCommands>
                    <summary>?</summary>
                    <syntax>?</syntax>
                    <use>?</use>
                </starCommand>
                ...
            </starCommands> 
            <url>?</url>
            <version>?</version>                
        </relocatableModule>
        ...
    </relocatableModules>    
    <services>
        <service>
            <address>?</address>
            <advertUrl>?</advertUrl>
            <category>?</category>
            <description territory="?">?</description>
            <email>?</email>
            <name>?</name>
            <pricing>
                <hourly currency="?">?</hourly>
            </pricing>
            <telephone>?</telephone>
            <url>?</url>
        </service>
        ...
    </services>
    <userGroups>
        <userGroup>
            <address>?</address>
            <advertUrl>?</advertUrl>
            <contact>?</contact>
            <description territory="?">?</description>
            <email>?</email>
            <name>?</name>
            <pricing>
                <subscription currency="?" duration="?">?</subscription>
            </pricing>
            <telephone>?</telephone>
            <url>?</url>
        </userGroup>
        ...
    </userGroups>
    <utilities>
        <utility>
            <name>?</name>
            <syntax>?</syntax>
            <url>?</url>
            <version>?</version>
        </utility>
        ...
    </utilities>
    <videos>
        <video>
            <description territory="?">?</description>
            <height>?</height>
            <title>?</title>
            <url>?</url>
            <width>?</width>
        </video>
        ...
    </videos>
</riscos>
'''
        modifiedFormat = self.post_process_xml_code(roml)
        
        content += '<p class="introduction"><table width="100%" border="0"><tr><th>RISC OS Markup Language</th><th>Change History</th></tr><tr><td><p align="left">'+modifiedFormat+'</p></td><td></td></tr></table></p>'

        content += '<p class="introduction">If you would like to suggest an addition or amendment to the RISC OS Markup Language, please submit your request to comp.sys.acorn.misc so that it may be debated in public and the most sensible resolution implemented.</p>'
        
        content += '<p class="introduction">Administration of the RISC OS Markup Language is currently in the hands of one person. Should you wish to join the committee to look after it into the future, please don\'t hesitate to email us.</p>'
        
        content += '<p class="introduction">Currently, there are a number of local riscos.xml file. These have been created for testing purposes and will be cut-down and/or removed in due course as and when records are replaced by external ones.</p>'
        
        content += '<p class="introduction">Although the RISC OS Markup Language is quite complex, you only have to include those sections applicable for your needs. Should you consider the RISC OS Markup Language syntax to be over-complicated, try searching for a record similar to the one you want to create and utilise its XML code as a starting point.</p>'
        content += '</div>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def riscos_xml_urls(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, nofollow')
        content += '<h2>riscos.xml URLs</h2>'
        content += '<p>The following riscos.xml files have been found on the World Wide Web</p>'
        riscosXmlFiles = self.riscosCollection.find({'riscos_xml':{'$exists':True}}).distinct('riscos_xml')
        riscosXmlFiles.sort()
        content += '<table class="software"><tr><th>Number</th><th>riscos.xml File</th></tr>'
        for i in range(len(riscosXmlFiles)):
            content += '<tr><td>'+str(i+1)+'</td><td align="left"><a href="'+riscosXmlFiles[i]+'" target="_blank">'+riscosXmlFiles[i]+'</a></td></tr>'
        #endfor
        content += '</table>'
        content += self.footer()
        return content
    #enddef
       
    @cherrypy.expose
    def rssfeed(self):
        content = ""
        content += '<?xml version="1.0" encoding="ISO-8859-1" ?>'
        content += '<rss version="2.0">'
        content += '<channel>'
        content += '<title>The RISC OS Search Engine RSS Feed</title>'
        content += '<link>http://www.shalfield.com/riscos</link>'
        content += '<description>A completely automated search engine for absolute files, applications, filetypes, fonts, relocatable modules, monitor definition files, printer definition files and utilities compatible with the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers</description>'
        content += '<item>'
        content += '<title>The RISC OS Search Engine</title>'
        content += '<link>http://www.shalfield.com/riscos</link>'
        content += '<description>A completely automated search engine for absolute files, applications, filetypes, fonts, relocatable modules, monitor definition files, printer definition files and utilities compatible with the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers</description>'
        content += '</item>'       
        
        content += '<item>'
        content += '<title>The RISC OS Search Engine source code now on GitHub!</title>'
        content += '<link>https://github.com/RebeccaShalfield/RISCOSSearchEngine</link>'
        content += '<description>Follow development of The RISC OS Search Engine on GitHub!</description>'
        content += '</item>'        
        
        apps = self.riscosCollection.find({'directory':{'$exists':True}}).distinct('directory')
        if apps:
            content += '<item>'
            content += '<title>The RISC OS Search Engine currently knows about '+str(len(apps))+' distinct RISC OS applications!</title>'
            content += '<link>http://www.shalfield.com/riscos</link>'
            content += '<description>The RISC OS Search Engine currently knows about '+str(len(apps))+' distinct RISC OS applications!</description>'
            content += '</item>'
        #endif
        
        modules = self.riscosCollection.find({'relocatable_modules.name':{'$exists':True}}).distinct('relocatable_modules.name')
        if modules:
            content += '<item>'
            content += '<title>The RISC OS Search Engine currently knows about '+str(len(modules))+' distinct RISC OS relocatable modules!</title>'
            content += '<link>http://www.shalfield.com/riscos</link>'
            content += '<description>The RISC OS Search Engine currently knows about '+str(len(modules))+' distinct RISC OS relocatable modules!</description>'
            content += '</item>'
        #endif
        
        utilities = self.riscosCollection.find({'utilities.name':{'$exists':True}}).distinct('utilities.name')
        if modules:
            content += '<item>'
            content += '<title>The RISC OS Search Engine currently knows about '+str(len(utilities))+' distinct RISC OS utilities!</title>'
            content += '<link>http://www.shalfield.com/riscos</link>'
            content += '<description>The RISC OS Search Engine currently knows about '+str(len(utilities))+' distinct RISC OS utilities!</description>'
            content += '</item>'
        #endif
        
        riscosXmlFiles = self.riscosCollection.find({'riscos_xml':{'$exists':True}}).distinct('riscos_xml')
        if len(riscosXmlFiles) > 0 and len(riscosXmlFiles) < 100:
            content += '<item>'
            content += '<title>The RISC OS Search Engine needs your riscos.xml files!</title>'
            content += '<link>http://www.shalfield.com/riscos</link>'
            content += '<description>The RISC OS Search Engine is currently able to read '+str(len(riscosXmlFiles))+' riscos.xml files but we need many more!</description>'
            content += '</item>'
        #endif

        glossaryTerms = self.riscosCollection.find({'glossary_term':{'$exists':True}}).distinct('glossary_term')
        if len(glossaryTerms) > 0:
            content += '<item>'
            content += '<title>The RISC OS Search Engine has '+str(len(glossaryTerms))+' RISC OS-related terms in its glossary!</title>'
            content += '<link>http://www.shalfield.com/riscos</link>'
            content += '<description>The RISC OS Search Engine has '+str(len(glossaryTerms))+' RISC OS-related terms in its glossary!</description>'
            content += '</item>'
        #endif
        
        content += '</channel>'
        content += '</rss>'
        return content
    #enddef
    
    @cherrypy.expose
    def atomfeed(self):
        content = ""
        content += '<?xml version="1.0" encoding="utf-8" ?>'
        content += '<feed xmlns="http://www.w3.org/2005/Atom">'
        content += '<title>The RISC OS Search Engine ATOM Feed</title>'
        content += '<subtitle>A completely automated search engine for absolute files, applications, filetypes, fonts, relocatable modules, monitor definition files, printer definition files and utilities compatible with the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers</subtitle>'
        content += '<link href="http://www.shalfield.com/riscos" />'
        
        content += '<entry>'
        content += '<title>The RISC OS Search Engine</title>'
        content += '<link href="http://www.shalfield.com/riscos" />'
        content += '<summary>A completely automated search engine for absolute files, applications, filetypes, fonts, relocatable modules, monitor definition files, printer definition files and utilities compatible with the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers</summary>'
        content += '</entry>'       
        
        content += '<entry>'
        content += '<title>The RISC OS Search Engine source code now on GitHub!</title>'
        content += '<link href="https://github.com/RebeccaShalfield/RISCOSSearchEngine" />'
        content += '<summary>Follow development of The RISC OS Search Engine on GitHub!</summary>'
        content += '</entry>'        
        
        apps = self.riscosCollection.find({'directory':{'$exists':True}}).distinct('directory')
        if apps:
            content += '<entry>'
            content += '<title>The RISC OS Search Engine currently knows about '+str(len(apps))+' distinct RISC OS applications!</title>'
            content += '<link href="http://www.shalfield.com/riscos" />'
            content += '<summary>The RISC OS Search Engine currently knows about '+str(len(apps))+' distinct RISC OS applications!</summary>'
            content += '</entry>'
        #endif
        
        modules = self.riscosCollection.find({'relocatable_modules.name':{'$exists':True}}).distinct('relocatable_modules.name')
        if modules:
            content += '<entry>'
            content += '<title>The RISC OS Search Engine currently knows about '+str(len(modules))+' distinct RISC OS relocatable modules!</title>'
            content += '<link href="http://www.shalfield.com/riscos" />'
            content += '<summary>The RISC OS Search Engine currently knows about '+str(len(modules))+' distinct RISC OS relocatable modules!</summary>'
            content += '</entry>'
        #endif
        
        utilities = self.riscosCollection.find({'utilities.name':{'$exists':True}}).distinct('utilities.name')
        if modules:
            content += '<entry>'
            content += '<title>The RISC OS Search Engine currently knows about '+str(len(utilities))+' distinct RISC OS utilities!</title>'
            content += '<link href="http://www.shalfield.com/riscos" />'
            content += '<summary>The RISC OS Search Engine currently knows about '+str(len(utilities))+' distinct RISC OS utilities!</summary>'
            content += '</entry>'
        #endif
        
        riscosXmlFiles = self.riscosCollection.find({'riscos_xml':{'$exists':True}}).distinct('riscos_xml')
        if len(riscosXmlFiles) > 0 and len(riscosXmlFiles) < 100:
            content += '<entry>'
            content += '<title>The RISC OS Search Engine needs your riscos.xml files!</title>'
            content += '<link href="http://www.shalfield.com/riscos" />'
            content += '<summary>The RISC OS Search Engine is currently able to read '+str(len(riscosXmlFiles))+' riscos.xml files but we need many more!</summary>'
            content += '</entry>'
        #endif

        glossaryTerms = self.riscosCollection.find({'glossary_term':{'$exists':True}}).distinct('glossary_term')
        if len(glossaryTerms) > 0:
            content += '<entry>'
            content += '<title>The RISC OS Search Engine has '+str(len(glossaryTerms))+' RISC OS-related terms in its glossary!</title>'
            content += '<link href="http://www.shalfield.com/riscos" />'
            content += '<summary>The RISC OS Search Engine has '+str(len(glossaryTerms))+' RISC OS-related terms in its glossary!</summary>'
            content += '</entry>'
        #endif
        
        content += '</feed>'
        return content
    #enddef
    
    @cherrypy.expose
    def syndicated_feeds(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, nofollow')
        content += '<h2>Syndicated Feeds</h2>'
        syndicatedFeeds = self.riscosCollection.find({'syndicated_feed':{'$exists':True,'$ne':""}}).distinct('syndicated_feed')
        if syndicatedFeeds:
            content += '<p>The following syndicated feeds have been found on the World Wide Web</p>'
            content += '<table class="software"><tr><th>Number</th><th>Syndicated Feed</th></tr>'
            syndicatedFeeds.sort()
            for i in range(len(syndicatedFeeds)):
                content += '<tr><td>'+str(i+1)+'</td><td align="left"><a href="'+syndicatedFeeds[i]+'" target="_blank">'+syndicatedFeeds[i]+'</a></td></tr>'
            #endfor
            content += '</table>'
        #endif
        content += self.footer()
        return content    
    #enddef
    
    @cherrypy.expose
    def synchronise(self):
        content = ""
        epoch = int(time.time())
        # Returns all riscos documents scanned in the last 48 hours
        if self.riscosCollection.find({'last_scanned':{'$gte':epoch-172800}}).count():
            for document in self.riscosCollection.find({'last_scanned':{'$gte':epoch-172800}}):
                okToSynchronise = True
                for urlKey in ['url','parent_url']:
                    if document.has_key(urlKey) and document[urlKey]:
                        (scheme,netloc,path,query,fragment) = urlparse.urlsplit(document[urlKey])
                        if self.blacklisted_domains.has_key(netloc):
                            okToSynchronise = False
                        #endif
                        if not self.trusted_domains.has_key(netloc):
                            okToSynchronise = False
                        #endif
                    #endif
                #endfor
                if okToSynchronise:
                    content += '{\n'
                    for key in document.keys():
                        if key != '_id':
                            try:
                                content += "'"+key + "' : '" + str(document[key]) + "'\n"
                            except:
                                True
                        #endif
                    #endfor
                    content += '}\n'
                #endif
            #endfor
        #endif
        return content
    #enddef

    @cherrypy.expose
    def spidering(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'noindex, follow')
        content += '<h2>Spidering</h2>'
        total = self.urlsCollection.find().count()
        riscosXmlFiles = self.urlsCollection.find({'riscos_xml':{'$exists':True}}).count()
        syndicatedFeeds = self.urlsCollection.find({'syndicated_feed':{'$exists':True}}).count()
        zipFiles = self.urlsCollection.find({'zip_file':{'$exists':True}}).count()
        misc = total - (riscosXmlFiles + syndicatedFeeds + zipFiles)
        content += '<table class="software">'
        content += '<tr><th rowspan="2">Total<br>(Unprocessed URLs)</th><th colspan="4">Breakdown</th></tr>'
        content += '<tr><th>riscos.xml Files</th><th>Syndicated Feeds</th><th>.zip Files</th><th>Miscellaneous</th></tr>'
        content += '<tr><td>'+str(total)+'</td><td>'+str(riscosXmlFiles)+'</td><td>'+str(syndicatedFeeds)+'</td><td>'+str(zipFiles)+'</td><td>'+str(misc)+'</td></tr>'
        content += '</table><p></p>'
        
        #domains = self.urlsCollection.find({'domain':{'$exists':True}}).distinct('domain')
        #if domains:
        #    content += '<table class="software"><tr>'
        #    for domain in domains:
        #        content += '<th>'+domain+'</th>'
        #    #endfor            
        #    content += '</tr>'
        #    content += '<tr>'
        #    for domain in domains:
        #        domainCount = self.urlsCollection.find({'domain':domain}).count()
        #        content += '<td>'+str(domainCount)+'</td>'
        #    #endfor
        #    content += '</tr></table>'
        ##endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def statistics(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'noindex, follow')
        content += '<h2>Statistics</h2>'
        
        content += '<h3>Attributes</h3>'

        rows = [('Absolutes','absolutes','list','ff8.png',{'absolutes':{"$exists":True,"$nin":["",[]]}}),
                ('Apps','directory','string','app.png',{'directory':{"$exists":True,"$nin":["",[]]}}),
                ('ARC Files','arc_file','string','',{'arc_file':{"$exists":True,"$nin":["",[]]}}),
                ('Authors','author','list','',{'authors':{"$exists":True,"$nin":["",[]]}}),
                ('Dealers','dealer','string','',{'dealer':{"$exists":True,"$nin":["",[]]}}),
                ('Developers','developer','string','',{'developer':{"$exists":True,"$nin":["",[]]}}),
                ('Filetypes','filetypes_run','list','',{'filetypes_run':{"$exists":True,"$nin":["",[]]}}),
                ('Fonts','fonts','list','ff6.png',{'fonts':{"$exists":True,"$nin":["",[]]}}),
                ('Forums','forum','string','',{'forum':{"$exists":True,"$nin":["",[]]}}),
                ('Glossary Terms','glossary_term','string','',{'glossary_term':{"$exists":True,"$nin":["",[]]}}),
                ('Maintainers','maintainer','string','',{'maintainer':{"$exists":True,"$nin":["",[]]}}),
                ('Monitor Definition Files','monitor_definition_files','list','display.png',{'monitor_definition_files':{"$exists":True,"$nin":["",[]]}}),
                ('Packages','package_name','string','package.png',{'package_name':{"$exists":True,"$nin":["",[]]}}),
                ('Page Titles','page_title','string','',{'page_title':{"$exists":True,"$nin":["",[]]}}),
                ('Portable Document Format Files','pdf_file','string','',{'pdf_file':{"$exists":True,"$nin":["",[]]}}),
                ('Printer Definition Files','printer_definition_files','list','',{'printer_definition_files':{"$exists":True,"$nin":["",[]]}}),
                ('Provider','provider','string','',{'provider':{"$exists":True,"$nin":["",[]]}}),
                ('Relocatable Modules','relocatable_modules.name','list','ffa.png',{'relocatable_modules.name':{"$exists":True,"$nin":["",[]]}}),
                ('Spark Files','spark_file','string','',{'spark_file':{"$exists":True,"$nin":["",[]]}}),
                ('* Command','star_command','list','',{'star_command':{"$exists":True,"$nin":["",[]]}}),
                ('System Variables','system_variables','list','',{'system_variables':{"$exists":True,"$nin":["",[]]}}),
                ('Utilities','utilities.name','list','ffc.png',{'utilities.name':{"$exists":True,"$nin":["",[]]}}),
                ('ZIP Files','zip_file','string','ddc.png',{'zip_file':{"$exists":True,"$nin":["",[]]}})
               ]
        content += '<table id="searchcriteria"><tr>'
        noInRow = 0
        for row in rows:
            if row[3]:
                content += '<th><img src="/riscos/images/'+row[3]+'" alt="'+row[3]+'"></th>'
            else:
                content += '<th></th>'
            #endif
            content += '<th>'+row[0]+'</th>'
            if row[2] == 'string':
                count = self.riscosCollection.find(row[4]).count()
            elif row[2] == 'list':
                distinctMembers = []
                listOfLists = self.riscosCollection.find(row[4]).distinct(row[1])
                for singleList in listOfLists:
                    for listMember in singleList:
                        if not listMember in distinctMembers:
                            distinctMembers.append(listMember)
                        #endif
                    #endfor
                #endfor
                count = len(distinctMembers)
            #endif
            content += '<td align="right"><h2>'+str(count)+'</h2></td>'
            noInRow += 1
            if noInRow == 3:
                content += '</tr><tr>'
                noInRow = 0
            #endif
        #endfor
        content += '</tr></table>'
        
        content += '<h3>ARM Architectures</h3>'
        
        content += '<table id="searchcriteria"><tr><th></th>'

        for (armArchitecture,modelsCovered) in self.armArchitectures:
            content += '<th>'+armArchitecture+'<br>'+modelsCovered+'</th>'
        #endfor
        content += '</tr><tr><th>Apps</th>'
        for (armArchitecture,modelsCovered) in self.armArchitectures:
            appsForArmArchitecture = 0
            for document in self.riscosCollection.find({'arm_architectures':{'$exists':True,'$ne':''},'directory':{'$exists':True,'$ne':''}}):
                if armArchitecture in document['arm_architectures']:
                    appsForArmArchitecture += 1
                #endif
            #endfor
            content += '<td>'+str(appsForArmArchitecture)+'</td>'
        #endfor            
        content += '</tr></table>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def filetypes(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, nofollow')
        content += '<h2>Filetypes</h2>'
        filetypesFound = []
        filetypes = []
        for field in ['filetypes_set','filetypes_run']:
            documents = self.riscosCollection.find({field:{'$exists':True}})
            for document in documents:
                for filetype in document[field]:
                    if filetype.__contains__(' '):
                        (hex,textual) = filetype.split(' ')
                        if not hex.upper() in filetypesFound and not (hex.upper(),textual) in filetypes:
                            filetypesFound.append(hex.upper())
                            filetypes.append((hex.upper(),textual))
                        #endif
                    else:
                        if not hex.upper() in filetypesFound and not (filetype.upper(),'') in filetypes:
                            filetypesFound.append(hex.upper())
                            filetypes.append((filetype.upper(),''))
                        #endif
                    #endif
                #endfor
            #endfor
        #endfor
        filetypes.sort()
        content += '<table class="software"><tr><th>Hex</th><th>Textual</th><th>Applications</th></tr>'
        for (hex,textual) in filetypes:
            content += '<tr><td><a href="/riscos/filetype?search='+hex+'">'+hex+'</a></td><td><a href="/riscos/filetype?search='+textual+'">'+textual+'</a></td><td>'
            apps = []
            for document in self.riscosCollection.find({'directory':{'$exists':True},'filetypes_set':{'$exists':True}}):
                if hex+' '+textual in document['filetypes_set']:
                    apps.append(document['directory'])
                #endif
            #endfor
            if apps:
                apps = list(set(apps))
                apps.sort()
                for app in apps:
                    content += '<form class="inline" action="/riscos/app?search='+app+'" method="post"><input class="button" type="submit" value="'+app+'"></form> '
                #endfor
            #endif
            content += '</td></tr>'
        #endfor
        content += '</table>'
        content += self.footer()
        return content
    #enddef     
    
    @cherrypy.expose
    def visitors(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'noindex, follow')
        remoteUserAgents = self.usersCollection.find({'user_agent':{'$ne':['']}}).distinct('user_agent')
        content += '<table id="searchcriteria"><tr><th>Remote User Agent</th><th>Count</th></tr>'
        for remoteUserAgent in remoteUserAgents:
            count = self.usersCollection.find({'user_agent':remoteUserAgent}).count()
            if remoteUserAgent.__contains__('RISC OS'):
                content += '<tr><td><b class="riscos">'+remoteUserAgent+'</b></td><td><b class="riscos">'+str(count)+'</b></td></tr>'
            else:
                content += '<tr><td>'+remoteUserAgent+'</td><td>'+str(count)+'</td></tr>'
            #endif
        #endfor
        content += '</table></div></body>'
        content += self.footer()
        return content
    #enddef
    
    def footer(self):
        content = "</div>"
        epoch = int(time.time())
        
        guestDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        
        # Get count of all URLs still to be spidered
        unprocessedUrlCount = self.urlsCollection.find().count()
        rejectedCount = self.rejectsCollection.find().count()
        quarantinedCount = self.quarantineCollection.find().count()
        reservedCount = self.reservesCollection.find().count()
        # Get count of all current URLs less than a year old
        processedUrlCount = self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-31536000}}).count()
        
        noOfMembers = len(self.usersCollection.find({"username":{"$exists":True,"$ne":""}}).distinct("username")) 
        visitorsTodayCount = self.usersCollection.find({"session_id":{"$exists":True,"$ne":""},'last_visit':{'$gte':epoch-86400}}).count()
        membersTodayCount = len(self.usersCollection.find({"session_id":{"$exists":True,"$ne":""},"logged_on":{"$exists":True,"$ne":""},'last_visit':{'$gte':epoch-86400}}).distinct("logged_on"))
        guestsTodayCount = visitorsTodayCount - membersTodayCount
        
        content += '<div id="footer_container">'
        content += '<div id="footer_contents"><form class="inline" action="/riscos/riscos_distributed_information_model" method="post"><input class="button" type="submit" value="RODIM" title="RISC OS Distributed Information Model"></form> <form class="inline" action="/riscos/riscos_markup_language" method="post"><input class="button" type="submit" value="ROML" title="RISC OS Markup Language"></form>'
        if guestDocument.has_key('member') and guestDocument['member']:
            content += '| <form class="inline" action="/riscos/submit_url" method="post"><input type="text" name="url"> <input class="button" type="submit" value="Submit URL"></form> '
        #endif
        content += '| <form class="inline" action="/riscos/how_you_can_help" method="post"><input class="button" type="submit" value="How You Can Help" title="How You Can Help"></form> <form class="inline" action="/riscos/quarantine" method="post"><input class="button" type="submit" value="Quarantine" title="Gives details of quarantined records"></form> <form class="inline" action="/riscos/spidering" method="post"><input class="button" type="submit" value="Spidering"></form> <form class="inline" action="/riscos/statistics" method="post"><input class="button" type="submit" value="Statistics"></form> <form class="inline" action="/riscos/key" method="post"><input class="button" type="submit" value="Key"></form> <form class="inline" action="/riscos/visitors" method="post"><input class="button" type="submit" value="Visitors"></form> <form class="inline" action="/riscos/sourcecode" method="post"><input class="button" type="submit" value="Source Code"></form><br>'
        content += 'Source Code Copyright &copy; Rebecca Shalfield 2002-2013'
        content += ' | URLs - Processed: '+str(processedUrlCount)+', Unprocessed: '+str(unprocessedUrlCount)+', Quarantined: '+str(quarantinedCount)+', Reserved: '+str(reservedCount)+', Rejected: '+str(rejectedCount)
        content += ' | No. of Members: '+str(noOfMembers)+' |  Guests Today: '+str(guestsTodayCount)+' |  Members Today: '+str(membersTodayCount)+' | <a href="/riscos/rssfeed" title="RSS Feed"><img src="/riscos/images/rssfeed.png" alt="RSS Feed" border="0"></a> <a href="/riscos/atomfeed" title="ATOM Feed"><img src="/riscos/images/rssfeed.png" alt="ATOM Feed" border="0"></a></div>'
        content += '</div>'
        content += '</body></html>'
        return content
    #enddef

    @cherrypy.expose
    def search_absolute_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['absolutes']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                if isinstance(document[attribute],list):
                    for item in document[attribute]:
                        if item.__contains__(term):
                            matches += item
                        #endif
                    #endfor
                elif isinstance(document[attribute],str):
                    matches += document[attribute]
                #endif
            #endif
        #endfor           
        if not matches:
            for attribute in ['absolutes']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_app_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_app_autocomplete'
        print term
        
        matches = []      
        if term.startswith('!'):
            distinctApps = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""}}).distinct("directory")
            for distinctApp in distinctApps:
                if distinctApp.lower().startswith(term.lower()):
                    matches.append(distinctApp)
                #endif            
            #endfor            
        else:
            for attribute in ['directory','application_name']:
                searchCriteria = {}
                searchCriteria[attribute] = term   
                document = self.riscosCollection.find_one(searchCriteria)
                if document:
                    if isinstance(document[attribute],list):
                        for item in document[attribute]:
                            if item.__contains__(term):
                                matches += item
                            #endif
                        #endfor
                    elif isinstance(document[attribute],str):
                        matches += document[attribute]
                    #endif
                #endif
            #endfor
        #endif            
        if not matches:
            for attribute in ['directory','application_name']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_errormessage_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []      
        for attribute in ['error_message']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['error_message']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_event_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_event_autocomplete'
        print term
        
        matches = []      
        for attribute in ['event']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['event']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_computer_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_computer_autocomplete'
        print term
        
        matches = []      
        for attribute in ['computer']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['computer']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_font_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['fonts']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                if isinstance(document[attribute],list):
                    for item in document[attribute]:
                        if item.__contains__(term):
                            matches += item
                        #endif
                    #endfor
                elif isinstance(document[attribute],str):
                    matches += document[attribute]
                #endif
            #endif
        #endfor           
        if not matches:
            for attribute in ['fonts']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_filetype_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['filetypes_set','filetypes_run']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            distinctFiletypes = self.riscosCollection.find(searchCriteria).distinct(attribute)
            for distinctFiletype in distinctFiletypes:
                if distinctFiletype.lower().__contains__(term.lower()):
                    matches.append(distinctFiletype)
                #endif
            #endfor
        #endfor           
        if not matches:
            for attribute in ['filetypes_set','filetypes_run']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                distinctFiletypes = self.riscosCollection.find(searchCriteria).distinct(attribute)
                for distinctFiletype in distinctFiletypes:
                    if distinctFiletype.lower().__contains__(term.lower()):
                        matches.append(distinctFiletype)
                    #endif
                #endfor
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_dealer_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_dealer_autocomplete'
        print term
        
        matches = []      
        for attribute in ['dealer']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['dealer']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_developer_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_developer_autocomplete'
        print term
        
        matches = []      
        for attribute in ['developer']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['developer']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef 
    
    @cherrypy.expose
    def search_forum_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_forum_autocomplete'
        print term
        
        matches = []      
        for attribute in ['forum']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['forum']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_video_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_video_autocomplete'
        print term
        
        matches = []      
        for attribute in ['video']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['video']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef  

    @cherrypy.expose
    def search_softwareinterrupt_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_softwareinterrupt_autocomplete'
        print term
        
        matches = []      
        for attribute in ['relocatable_modules.software_interrupts.name']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['relocatable_modules.software_interrupts.name']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef 
    
    @cherrypy.expose
    def search_starcommand_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_starcommand_autocomplete'
        print term
        
        matches = []      
        for attribute in ['relocatable_modules.star_commands.name']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['relocatable_modules.star_commands.name']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef 
    
    @cherrypy.expose
    def search_service_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_service_autocomplete'
        print term
        
        matches = []      
        for attribute in ['provider']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['provider']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef     
    
    @cherrypy.expose
    def search_faq_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []      
        for attribute in ['question']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['question']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef    
    
    @cherrypy.expose
    def search_howto_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_howto_autocomplete'
        print term
        
        matches = []      
        for attribute in ['howto']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['howto']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef     
    
    @cherrypy.expose
    def search_glossary_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_glossary_autocomplete'
        print term
        
        matches = []      
        for attribute in ['glossary_term']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['glossary_term']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_module_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['relocatable_modules.name','module_dependencies.name']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            distinctModules = self.riscosCollection.find(searchCriteria).distinct(attribute)
            for distinctModule in distinctModules:
                if distinctModule.lower().__contains__(term.lower()):
                    matches.append(distinctModule)
                #endif
            #endfor
        #endfor           
        if not matches:
            for attribute in ['relocatable_modules.name','module_dependencies.name']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                distinctModules = self.riscosCollection.find(searchCriteria).distinct(attribute)
                for distinctModule in distinctModules:
                    if distinctModule.lower().__contains__(term.lower()):
                        matches.append(distinctModule)
                    #endif
                #endfor
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_monitor_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['monitor_definition_files']:
            searchCriteria = {}
            searchCriteria[attribute] = term
            distinctMonitors = self.riscosCollection.find(searchCriteria).distinct(attribute)
            for distinctMonitor in distinctMonitors:
                if distinctMonitor.lower().__contains__(term.lower()):
                    matches.append(distinctMonitor)
                #endif
            #endfor
        #endfor           
        if not matches:
            for attribute in ['monitor_definition_files']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                distinctMonitors = self.riscosCollection.find(searchCriteria).distinct(attribute)
                for distinctMonitor in distinctMonitors:
                    if distinctMonitor.lower().__contains__(term.lower()):
                        matches.append(distinctMonitor)
                    #endif
                #endfor
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_podule_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_podule_autocomplete'
        print term
        
        matches = []      
        for attribute in ['podule']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['podule']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_printer_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['printer_definition_files']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                if isinstance(document[attribute],list):
                    for item in document[attribute]:
                        if item.__contains__(term):
                            matches += item
                        #endif
                    #endfor
                elif isinstance(document[attribute],str):
                    matches += document[attribute]
                #endif
            #endif
        #endfor           
        if not matches:
            for attribute in ['printer_definition_files']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_peripheral_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['peripheral']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                if isinstance(document[attribute],list):
                    for item in document[attribute]:
                        if item.__contains__(term):
                            matches += item
                        #endif
                    #endfor
                elif isinstance(document[attribute],str):
                    matches += document[attribute]
                #endif
            #endif
        #endfor           
        if not matches:
            for attribute in ['peripheral']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_project_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['project']:
            searchCriteria = {}
            searchCriteria[attribute] = term   
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                if isinstance(document[attribute],list):
                    for item in document[attribute]:
                        if item.__contains__(term):
                            matches += item
                        #endif
                    #endfor
                elif isinstance(document[attribute],str):
                    matches += document[attribute]
                #endif
            #endif
        #endfor           
        if not matches:
            for attribute in ['project']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_book_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_book_autocomplete'
        print term
        
        matches = []      
        for attribute in ['book']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['book']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef    
    
    @cherrypy.expose
    def search_magazine_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_magazine_autocomplete'
        print term
        
        matches = []      
        for attribute in ['magazine']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['magazine']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_usergroup_autocomplete(self, term):
        status = self.cookie_handling()
        
        print 'search_usergroup_autocomplete'
        print term
        
        matches = []      
        for attribute in ['user_group']:
            searchCriteria = {}
            searchCriteria[attribute] = term  
            document = self.riscosCollection.find_one(searchCriteria)
            if document:
                matches += document[attribute]
            #endif
        #endfor           
        if not matches:
            for attribute in ['user_group']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_utility_autocomplete(self, term):
        status = self.cookie_handling()
        matches = []
        for attribute in ['utilities.name']:
            searchCriteria = {}
            searchCriteria[attribute] = term
            distinctUtilities = self.riscosCollection.find(searchCriteria).distinct(attribute)
            for distinctUtility in distinctUtilities:
                if distinctUtility.lower().__contains__(term.lower()):
                    matches.append(distinctUtility)
                #endif
            #endfor
        #endfor           
        if not matches:
            for attribute in ['utilities.name']:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                distinctUtilities = self.riscosCollection.find(searchCriteria).distinct(attribute)
                for distinctUtility in distinctUtilities:
                    if distinctUtility.lower().__contains__(term.lower()):
                        matches.append(distinctUtility)
                    #endif
                #endfor
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
    @cherrypy.expose
    def search_autocomplete(self, term):
        status = self.cookie_handling()
        attributesToSearch = []
        for (externalAttribute,internalAttribute,key) in self.searchableAttributes:
            attributesToSearch.append(internalAttribute)
        #endfor
        matches = []      
        if term.startswith('!'):
            distinctApps = self.riscosCollection.find({"directory":{"$exists":True,"$ne":""}}).distinct("directory")
            for distinctApp in distinctApps:
                if distinctApp.lower().startswith(term.lower()):
                    matches.append(distinctApp)
                #endif            
            #endfor            
        else:
            for attribute in attributesToSearch:
                searchCriteria = {}
                searchCriteria[attribute] = term   
                document = self.riscosCollection.find_one(searchCriteria)
                if document:
                    if isinstance(document[attribute],list):
                        for item in document[attribute]:
                            if item.__contains__(term):
                                matches += item
                            #endif
                        #endfor
                    elif isinstance(document[attribute],str):
                        matches += document[attribute]
                    #endif
                #endif
            #endfor
        #endif            
        if not matches:
            for attribute in attributesToSearch:
                searchCriteria = {}
                searchCriteria[attribute] = re.compile('(?i)'+term)     
                matches += self.riscosCollection.find(searchCriteria).limit(3).distinct(attribute)
            #endfor
        #endif
        content = '['
        for i in range(len(matches)):
            content += '"'+matches[i].replace('"','\\"')+'"'
            if i < len(matches)-1:
                content += ','
            #endif
        #endfor
        content += ']'
        return content
    #enddef
    
#endclass

current_dir = os.path.dirname(os.path.abspath(__file__))

conf = { '/'           : { 'tools.staticdir.root'      : current_dir },
         '/riscos.css' : { 'tools.staticfile.on'       : True,
                           'tools.staticfile.filename' : current_dir + os.sep + 'riscos.css'
                         },
         '/riscos.js' : { 'tools.staticfile.on'        : True,
                           'tools.staticfile.filename' : current_dir + os.sep + 'riscos.js'
                         },
         '/riscos.xml' : { 'tools.staticfile.on'        : True,
                           'tools.staticfile.filename' : current_dir + os.sep + 'riscos.xml'
                         },
         '/riscos.xsl' : { 'tools.staticfile.on'        : True,
                           'tools.staticfile.filename' : current_dir + os.sep + 'riscos.xsl'
                         },
         '/softwareconfirmed'     : { 'tools.staticdir.on'      : True,
                           'tools.staticdir.dir'       : 'softwareconfirmed'
                         },
         '/riscosxml'     : { 'tools.staticdir.on'      : True,
                           'tools.staticdir.dir'       : 'riscosxml'
                         },
         '/images'     : { 'tools.staticdir.on'        : True,
                           'tools.staticdir.dir'       : 'images'
                         },
         '/downloads'  : { 'tools.staticdir.on'        : True,
                           'tools.staticdir.dir'       : 'downloads'
                         },
         '/jquery-ui-1.8.21.custom' : { 'tools.staticdir.on'        : True,
                                        'tools.staticdir.dir'       : current_dir + os.sep + 'jquery-ui-1.8.21.custom'
                                      }
       }

cherrypy.tree.mount(riscos(), '/riscos', config=conf)
