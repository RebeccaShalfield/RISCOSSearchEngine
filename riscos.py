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
        
        self.mirror = 'www.shalfield.com/riscos'
        self.mirrors = ['84.92.157.78/riscos','www.shalfield.com/riscos','192.168.88.1:8081/riscos']
        
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
                                    ('Application Directory','application_directory','app.png'),
                                    ('Application Version','application_version',''),
                                    ('Dealer','dealer',''),
                                    ('Date','date',''),
                                    ('Purpose','purpose',''),
                                    ('Description','description',''),                                   
                                    ('Filetypes Read','filetypes_read',''),
                                    ('Filetypes Set','filetypes_set',''),
                                    ('Absolutes','absolutes','ff8.png'),
                                    ('Utilities','utilities','ffc.png'),
                                    ('Relocatable Modules','relocatable_modules','ffa.png'),
                                    ('Relocatable Modules Dependant Upon','relocatable_modules_dependant_upon','ffa.png'),
                                    ('Programming Languages','programming_languages',''),
                                    ('Fonts','fonts','ff6.png'),
                                    ('Help','help','help.png'),
                                    ('DTP Formats','dtp_formats',''),
                                    ('Minimum RISC OS Versions','minimum_riscos_versions',''),
                                    ('Monitor Definition Files','monitor_definition_files','display.png'),
                                    ('Printer Definition Files','printer_definition_files',''),
                                    ('* Commands','star_commands',''),
                                    ('System Variables','system_variables',''),
                                    ('Territories','territories',''),
                                    ('Source','source',''),
                                    ('Price','price',''),
                                    ('Author','author',''),
                                    ('Event','event',''),
                                    ('Video','video',''),
                                    ('Developer','developer',''),
                                    ('Provider','provider',''),
                                    ('Publisher','publisher',''),
                                    ('Forum','forum',''),
                                    ('Book','book',''),
                                    ('Magazine','magazine',''),
                                    ('User Group','user_group',''),
                                    ('Identifier','identifier',''),
                                    ('Address','address',''),
                                    ('Email','email',''),
                                    ('Telephone','telephone',''),
                                    ('Copyright','copyright',''),
                                    ('License','license',''),
                                    ('Package Name','package_name','package.png'),
                                    ('Package Section','package_section',''),
                                    ('Package Version','package_version',''),
                                    ('Categories','categories',''),
                                    ('Maintainer','maintainer',''),
                                    ('Priority','priority',''),
                                    ('Page Title','page_title',''),
                                    ('Glossary Term','glossary_term',''),
                                    ('Glossary Definition','glossary_definition',''),
                                    ('RSS Feed','rss_feed',''),
                                    ('RSS Feed Item Date','rss_feed_item_date',''),
                                    ('RSS Feed Item Description','rss_feed_item_description',''),
                                    ('RSS Feed Item Link','rss_feed_item_link',''),
                                    ('RSS Feed Item Title','rss_feed_item_title',''),
                                    ('URL','url',''),
                                    ('Parent URL','parent_url',''),
                                    ('Last Modified','last_modified',''),
                                    ('Last Scanned','last_scanned',''),
                                    ('Next Scan','next_scan','')
                                    ]        
        
        self.searchableAttributes = [
                                     ('Absolutes','absolutes','The name of an ARM code file'),
                                     ('Application Directory','application_directory','The name of a directory containing an application'),
                                     ('Application Name','application_name','The textual name of an application'),
                                     ('Application Version','application_version','The version of an application'),
                                     ('ARC File','arc_file','A legacy Acorn archive file format with a .arc extension'),
                                     ('Author','author','The author of an application'),
                                     ('Book','book','The title of a RISC OS-related book'),
                                     ('Categories','categories','The category to which an application has been assigned within a package'),
                                     ('Computer','computer','An ARM-powered computer capable of running RISC OS natively'),
                                     ('Copyright','copyright','An application\'s copyright message'),
                                     ('Date','date','The date of an application'),
                                     ('Dealer','dealer',"The name of a RISC OS dealer"),
                                     ('Description','description','The description of an application'),
                                     ('Developer','developer',"The name of a RISC OS hardware or software developer"),
                                     ('Domain','domain',"A web site's domain name"),
                                     ('DTP Formats','dtp_formats','Any desktop publishing files utilised within an application'),
                                     ('Event','event','The title of a RISC OS-related event'),
                                     ('Filetypes Read','filetypes_read','The filetypes readable by an application'),
                                     ('Filetypes Set','filetypes_set','The filetypes set by an application'),
                                     ('Fonts','fonts','Any fonts defined within an application'),
                                     ('Forum','forum','The name of a RISC OS-related forum'),
                                     ('Glossary Term','glossary_term','A term in the RISC OS Glossary'),
                                     ('Glossary Definition','glossary_definition','The meaning of a term in the RISC OS Glossary'),
                                     ('Help','help','The contents of the !Help file found within an application directory'),
                                     ('Identifier','identifier','The ISBN or ISSN of a RISC OS-related book or magazine respectively'),
                                     ('License','license','The application\'s license type'),
                                     ('Magazine','magazine','The title of a RISC OS-related magazine'),
                                     ('Maintainer','maintainer','The maintainer for a package'),
                                     ('Monitor Definition Files','monitor_definition_files','The driver for a monitor'),
                                     ('Package Name','package_name','The name of a package'),
                                     ('Package Section','package_section','The section for a package'),
                                     ('Package Version','package_version','The version of a package'),
                                     ('Page Title','page_title','The title of an HTML page as extracted from within the title tag'),
                                     ('Podule','podule','An expansion card for a RISC OS computer'),
                                     ('Portable Document Format File','pdf_file','Adobe-format files with a .pdf extension'),
                                     ('Price','price','The price of a RISC OS product'),
                                     ('Printer Definition Files','printer_definition_files','The driver for a printer'),
                                     ('Priority','priority','As set by the package'),
                                     ('Programming Languages','programming_languages','The programming language(s) an application is written in'),
                                     ('Provider','provider','The name of an entity providing a service to the RISC OS Community'),
                                     ('Publisher','publisher','The publisher of a RISC OS-related book or magazine'),
                                     ('Purpose','purpose','The purpose of an applicatiion'),
                                     ('Relocatable Modules','relocatable_modules','Modules contained within an application directory'),
                                     ('Relocatable Modules Dependant Upon','relocatable_modules_dependant_upon','Modules an application is dependant upon'),
                                     ('RSS Feed','rss_feed','The URL of an RSS Feed'),
                                     ('RSS Feed Item Date','rss_feed_item_date','The date an RSS Feed item was added to our database'),
                                     ('RSS Feed Item Description','rss_feed_item_description','The description associated with an RSS Feed item'),
                                     ('RSS Feed Item Link','rss_feed_item_link','The link associated with an RSS Feed item'),
                                     ('RSS Feed Item Title','rss_feed_item_title','The title of an RSS Feed item'),
                                     ('* Commands','star_commands','Sorry, not implemented yet!'),
                                     ('Source','source','The source of the package'),
                                     ('Spark File','spark_file','A legacy Acorn archive file format with a .spk extension'),
                                     ('System Variables','system_variables','Environment variables set by an application'),
                                     ('User Group','user_group','The name of a RISC OS-related user group'),
                                     ('Utilities','utilities','The name of a utility'),
                                     ('Video','video','The name of a RISC OS-related video'),
                                     ('ZIP File','zip_file','The name of a .zip file, the format for the RISC OS Packaging Project')
                                     ]
        
        self.riscosVersions = [('5.00','5.00')]
        osvers = []
        documents = self.riscosCollection.find({'relocatable_modules_dependant_upon.name':'UtilityModule'})
        for document in documents:
            for item in document['relocatable_modules_dependant_upon']:
                if item.has_key('name') and item['name'] == 'UtilityModule':
                    if item.has_key('version') and item['version'] and len(item['version']) == 4 and not item['version'] in osvers:
                        osvers.append(item['version'])
                    #endif
                #endif
            #endfor
        #endfor
        osvers.sort()
        for osver in osvers:
            if not (osver,osver) in self.riscosVersions:
                self.riscosVersions.append((osver,osver))
            #endif
        #endfor
        self.riscosVersions.sort()
        
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
        
        self.riscosspider = riscosspider.riscosspider()
        
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
            count = self.riscosCollection.find({'_id':ObjectId(doc_id)}).count()
            if count:
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
    def add_to_basket(self, doc_id, origin, nested=False):
        status = self.cookie_handling()
        if doc_id:
            count = self.riscosCollection.find({'_id':ObjectId(doc_id)}).count()
            if count:
                userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
                if userDocument.has_key('basket'):
                    userDocument['basket'].append(doc_id)
                else:
                    userDocument['basket'] = [doc_id]
                #endif
                self.usersCollection.save(userDocument)
            #endif
        #endif
        if origin == 'advanced':
            if nested:
                raise cherrypy.HTTPRedirect("/riscos/advanced?nested=true", 302)
            else:
                raise cherrypy.HTTPRedirect("/riscos/advanced", 302)
            #endif
        else:
            raise cherrypy.HTTPRedirect("/riscos/"+origin, 302)
        #endif
    #enddef
    
    @cherrypy.expose
    def switch_mirror(self, mirror):
        raise cherrypy.HTTPRedirect('http://'+mirror, 302)
    #enddef
    
    @cherrypy.expose
    def remove_from_basket(self, doc_id, origin, nested=False):
        status = self.cookie_handling()
        if doc_id:
            userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
            if userDocument.has_key('basket') and doc_id in userDocument['basket']:
                items = userDocument['basket']
                basketItems = []
                for item in items:
                    if item != doc_id:
                        basketItems.append(item)
                    #endif
                #endfor
                userDocument['basket'] = basketItems
                self.usersCollection.save(userDocument)
            #endif
        #endif
        if origin == 'advanced':
            if nested:
                raise cherrypy.HTTPRedirect("/riscos/advanced?nested=true", 302)
            else:
                raise cherrypy.HTTPRedirect("/riscos/advanced", 302)
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
            content += '<tr><td><p class="introduction">If you\'re already a registered member, you may logon here by entering your username and password</p></td><td><p class="introduction">You may register as a member by completing the form below. The primary benefit of becoming a member is that your filter settings will be remembered from one visit to the next.</p></td></tr>'
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
    def view_basket(self, nested=False):
        status = self.cookie_handling()
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument.has_key('basket') and userDocument['basket']:
            content = ""
            content += self.header(status, 'noindex, follow')
            if userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                content += self.display_document_table(userDocument['basket'], 'view_basket', nested)
            else:
                content += self.display_document_report(userDocument['basket'], 'view_basket', nested)
            #endif
            content += '</div></body>'
            content += self.footer()
            return content
        else:
            if nested:
                raise cherrypy.HTTPRedirect("/riscos/advanced?nested=true", 302)
            else:
                raise cherrypy.HTTPRedirect("/riscos/index", 302)
            #endif
        #endif
    #enddef
    
    @cherrypy.expose
    def clear_basket(self, nested=False):
        status = self.cookie_handling()
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        if userDocument.has_key('basket') and userDocument['basket']:
            userDocument['basket'] = []
            self.usersCollection.save(userDocument)
        #endif
        if nested:
            raise cherrypy.HTTPRedirect("/riscos/advanced?nested=true", 302)
        else:
            raise cherrypy.HTTPRedirect("/riscos/index", 302)
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
            selectedView = 'report'
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
        content += '</head>'
        content += '<body>'
        content += '<table id="header">'
        content += '<tr><th rowspan="4"><a href="/riscos/index" target="_top"><img src="/riscos/images/cogwheel.gif" alt="Cogwheel"></a></th><th class="filter" align="right">Mirror: <form class="inline" action="/riscos/switch_mirror" method="post"><select name="mirror" title="Select mirror">'
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
        content += '<tr><th><h1 id="title"><sup>The</sup> RISC OS Search Engine<br><sup><i><form class="inline" action="/riscos/absolute" method="post"><input class="button" type="submit" value="Absolutes" title="Search for Absolutes"></form> <form class="inline" action="/riscos/app" method="post"><input class="button" type="submit" value="Apps" title="Search for Applications"></form> <form class="inline" action="/riscos/book" method="post"><input class="button" type="submit" value="Books" title="Search for Books"></form> <form class="inline" action="/riscos/computer" method="post"><input class="button" type="submit" value="Computers" title="Search for Computers"></form> <form class="inline" action="/riscos/dealer" method="post"><input class="button" type="submit" value="Dealers" title="Search for Dealers"></form> <form class="inline" action="/riscos/developer" method="post"><input class="button" type="submit" value="Developers" title="Search for Developers"></form> <form class="inline" action="/riscos/event" method="post"><input class="button" type="submit" value="Events" title="Search for Events"></form> <form class="inline" action="/riscos/filetype" method="post"><input class="button" type="submit" value="Filetypes" title="Search for Filetypes"></form> <form class="inline" action="/riscos/font" method="post"><input class="button" type="submit" value="Fonts" title="Search for Fonts"></form> <form class="inline" action="/riscos/forum" method="post"><input class="button" type="submit" value="Forums" title="Search for Forum"></form> <form class="inline" action="/riscos/glossary" method="post"><input class="button" type="submit" value="Glossary" title="Search for Glossary Term"></form> <form class="inline" action="/riscos/magazine" method="post"><input class="button" type="submit" value="Magazines" title="Search for Magazines"></form> <form class="inline" action="/riscos/module" method="post"><input class="button" type="submit" value="Modules" title="Search for Relocatable Modules"></form> <form class="inline" action="/riscos/monitor" method="post"><input class="button" type="submit" value="Monitor DFs" title="Search for Monitor Definition Files"></form> <form class="inline" action="/riscos/podule" method="post"><input class="button" type="submit" value="Podules" title="Search for Podules"></form> <form class="inline" action="/riscos/printer" method="post"><input class="button" type="submit" value="Printer DFs" title="Search for Printer Definition Files"></form> <form class="inline" action="/riscos/service" method="post"><input class="button" type="submit" value="Services" title="Search for Services"></form> <form class="inline" action="/riscos/usergroup" method="post"><input class="button" type="submit" value="User Groups" title="Search for User Groups"></form> <form class="inline" action="/riscos/utility" method="post"><input class="button" type="submit" value="Utilities" title="Search for Utilities"></form> <form class="inline" action="/riscos/video" method="post"><input class="button" type="submit" value="Videos" title="Search for Videos"></form></i></sup></h1></th></tr>'
        content += '<tr><td class="filter"><form class="inline" action="/riscos/filter" method="post">'
        content += '<table class="filter"><tr><td>RISC OS Version</td><td>Addressing Mode</td><td>ARM Architecture</td><td>Territory</td><td>Start Year</td><td>End Year</td><td>View</td><td>Web Sites</td></tr>'       
        content += '<tr><td><select name="riscosversion" title="Select your version of RISC OS noting that 5.xx is in one fork and 4.xx/6.xx in the other">'
        selectedRiscosVersion, selectedAddressingMode, selectedArmArchitecture, selectedTerritory, selectedStartYear, selectedEndYear, selectedView, selectedWebsites = self.get_filter_settings(userDocument)
        for (textualRiscosVersion,riscosVersion) in self.riscosVersions:
            if selectedRiscosVersion and riscosVersion == selectedRiscosVersion:
                content += '<option value="'+riscosVersion+'" selected>'+textualRiscosVersion+'</option>'
            else:
                content += '<option value="'+riscosVersion+'">'+textualRiscosVersion+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="addressingmode" title="Select the addressing mode, 26-bit (older) or 32-bit (newer), used by RISC OS">'
        for addressingMode in ['26-bit','32-bit']:
            if addressingMode == selectedAddressingMode:
                content += '<option value="'+addressingMode+'" selected>'+addressingMode+'</option>'
            else:
                content += '<option value="'+addressingMode+'">'+addressingMode+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="armarchitecture" title="Sorry, ARM architecture is not utilised yet!">'
        for armArchitecture in ['ARMv3','ARMv4','ARMv5','ARMv6','ARMv7']:
            if armArchitecture == selectedArmArchitecture:
                content += '<option value="'+armArchitecture+'" selected>'+armArchitecture+'</option>'
            else:
                content += '<option value="'+armArchitecture+'">'+armArchitecture+'</option>'
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
        for startYear in range(1987,time.localtime()[0]+1):
            if startYear == int(selectedStartYear):
                content += '<option value="'+str(startYear)+'" selected>'+str(startYear)+'</option>'
            else:
                content += '<option value="'+str(startYear)+'">'+str(startYear)+'</option>'
            #endif
        #endfor
        content += '</select></td><td><select name="endyear">'
        for endYear in range(1987,time.localtime()[0]+1):
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
        content += '<tr><th><form class="inline" action="/riscos/introduction" method="post"><input class="button" type="submit" value="Introduction"></form> <form class="inline" action="/riscos/news" method="post"><input class="button" type="submit" value="News"></form> <form class="inline" action="/riscos/latestapps" method="post"><input class="button" type="submit" value="Latest Apps"></form> <form class="inline" action="/riscos/categorisation"><input class="button" type="submit" value="Categorisation"></form> <form class="inline" action="/riscos/index" method="post"><input class="button" type="submit" value="Generic Search" title="Allows you to enter a single search as either a string or a regular expression"></form> <form class="inline" action="/riscos/advanced" method="post"><input class="button" type="submit" value="Advanced Search" title="Allows you to enter multiple searches as regular expressions"></form> <form class="inline" action="/riscos/websites" method="post"><input class="button" type="submit" value="Web Sites"></form> <form class="inline" action="/riscos/ftpsites" method="post"><input class="button" type="submit" value="FTP Sites"></form> <form class="inline" action="/riscos/randomapp" method="post"><input class="button" type="submit" value="Random App" title="Displays details of a RISC OS application at random"></form> <form class="inline" action="/riscos/randomurl" method="post"><input class="button" type="submit" value="Random URL" title="Takes you to a URL at random directly related to a RISC OS application"></form> <form class="inline" action="/riscos/randomglossary" method="post"><input class="button" type="submit" value="Random Glossary" title="Displays a glossary term at random"></form> <form class="inline" action="/riscos/randomvideo" method="post"><input class="button" type="submit" value="Random Video" title="Takes you to a RISC OS-related video at random"></form> <form class="inline" action="/riscos/reports" method="post"><input class="button" type="submit" value="Reports"></form>'
        if userDocument and userDocument.has_key('basket') and userDocument['basket']:
            content += ' | <form class="inline" action="/riscos/view_basket" method="post">'
            if nested:
                content += '<input type="hidden" name="nested" value="true">'
            #endif
            content += '<input class="basket" type="submit" value="View" title="Display contents of basket"></form> <form class="inline" action="/riscos/clear_basket" method="post">'
            if nested:
                content += '<input type="hidden" name="nested" value="true">'
            #endif            
            content += '<input class="basket" type="submit" value="Clear" title="Empty basket"></form>'
        #endif
        content += '</th></tr>'
        content += '</table>'
        content += '<div class="maincontent">'
        if status == "new":
            content += '<h3 class="warning">We use cookies to ensure that we give you the best experience on our website<br>If you continue without changing your settings, we\'ll assume that you are happy to receive all cookies from this website</h3>'        
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
        distinctApps = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""}}).distinct("application_directory")
        appFound = False
        while not appFound:
            randomNo = randint(0,len(distinctApps)-1)
            doc_ids = self.riscosCollection.find({"application_directory":distinctApps[randomNo]}).distinct('_id')
            filteredDocIds = self.apply_filter(userDocument, doc_ids)
            if filteredDocIds:
                content += '<h3>'+str(randomNo+1)+' of '+str(len(distinctApps))+'</h3>'
                if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
                    content += self.display_document_table(filteredDocIds, 'randomapp', False)
                else:
                    content += self.display_document_report(filteredDocIds, 'randomapp', False)
                #endif
                appFound = True
            #endif
        #endwhile
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def randomglossary(self):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, nofollow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += '<h2>Random Glossary</h2>'     
        distinctTerms = self.riscosCollection.find({"glossary_term":{"$exists":True,"$ne":""},"glossary_definition":{"$exists":True,"$ne":""}}).distinct("glossary_term")
        termFound = False
        while distinctTerms and not termFound:
            randomNo = randint(0,len(distinctTerms)-1)
            doc_ids = self.riscosCollection.find({"glossary_term":distinctTerms[randomNo]}).distinct('_id')
            # Filtering on glossary terms currently has no effect
            filteredDocIds = self.apply_filter(userDocument, doc_ids)
            if filteredDocIds:
                content += '<h3>'+str(randomNo+1)+' of '+str(len(distinctTerms))+'</h3>'
                content += '<dl>'
                for filteredDocId in filteredDocIds:
                    document = self.riscosCollection.find_one({'_id':ObjectId(filteredDocId)})
                    content += '<dt>'+document['glossary_term']+'</dt>'
                    content += '<dd>'+document['glossary_definition']+'</dd>'
                #endfor
                content += '</dl>'
                termFound = True
            #endif
        #endwhile
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
                        content += '<p>'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+self.insert_last_modified_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</p>'
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
        distinctUrls = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""},"parent_url":{"$exists":True,"$ne":""}}).distinct("parent_url")
        if distinctUrls:
            urlFound = False
            while not urlFound:
                randomNo = randint(0,len(distinctUrls)-1)
                doc_ids = self.riscosCollection.find({"parent_url":distinctUrls[randomNo]}).distinct('_id')
                filteredDocIds = self.apply_filter(userDocument, doc_ids)
                if filteredDocIds:
                    selectedUrl = distinctUrls[randomNo]
                    distinctApps = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""},"parent_url":selectedUrl}).distinct("application_directory")
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
            count = self.urlsCollection.find({'url':url}).count()
            if not count:
                newDocument = {}
                newDocument['url'] = url
                if url.lower().endswith('.zip'):
                    newDocument['zip_file'] = url
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
            #endif
            count = self.riscosCollection.find({'url':url}).count()
            if count:
                for existingDocument in self.riscosCollection.find({'url':url}):
                    self.riscosCollection.remove({'_id':ObjectId(existingDocument['_id'])})
                #endfor
            #endif
        #endif
        raise cherrypy.HTTPRedirect("/riscos/index", 302)
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
                            raise cherrypy.HTTPRedirect("/riscos/advanced", 302)
                        #endif
                    #endif
                #endif
            #endif
        #endif
        raise cherrypy.HTTPRedirect("/riscos/advanced?removal=true", 302)
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
    def index(self, format="string", search=''):
        content = ""
        status = self.cookie_handling()
        content += self.header(status, 'index, follow')
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())

        # This code deals with legacy user documents where last_scanned was used instead of last_visit
        for userDocument in self.usersCollection.find({}):
            if userDocument.has_key('last_scanned'):
                userDocument['last_visit'] = userDocument['last_scanned']
                del userDocument['last_scanned']
                self.usersCollection.save(userDocument)
            #endif
        #endfor
        
        if not search:
            # Delete guest documents older than 28 days
            oldGuestDocuments = self.usersCollection.find({'last_visit':{'$lt':epoch-2419200},"username":{"$exists":False}})
            for oldGuestDocument in oldGuestDocuments:
                self.usersCollection.remove({'_id':ObjectId(oldGuestDocument['_id'])})
            #endfor
        #endif
        
        if userDocument:
            if userDocument.has_key("last_visit") and userDocument["last_visit"]:
                # Reset search if last visit was over 24 hours ago
                if userDocument["last_visit"]+86400 <= epoch:
                    userDocument['search_criteria'] = {}
                    userDocument['key'] = ""
                    userDocument['value'] = ""
                    userDocument['basket'] = []
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
        
        content += '<p><form action="/riscos/index" method="post">'
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
                    if attributeToSearch in ['relocatable_modules','relocatable_modules_dependant_upon','utilities']:
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
            #endif
            
        else:
            content += '<div id="introduction">'
            content += '<p class="introduction">What Others Have Been Searching For During The Past 28 Days</p>'
            otherUserDocuments = self.usersCollection.find({"session_id":{"$exists":True,"$ne":""},"value":{"$exists":True,"$ne":""},'last_visit':{'$gte':epoch-2419200}})
            if otherUserDocuments:
                otherSearches = []
                for otherUserDocument in otherUserDocuments:
                    if otherUserDocument.has_key('format') and otherUserDocument.has_key('value') and otherUserDocument['format'] and otherUserDocument['value']:
                        if not (otherUserDocument['value'].lower(),otherUserDocument['format'],otherUserDocument['value']) in otherSearches:
                            otherSearches.append((otherUserDocument['value'].lower(),otherUserDocument['format'],otherUserDocument['value']))
                        #endif
                    #endif
                #endfor
                if otherSearches:
                    otherSearches.sort()
                    content += '<ul>'
                    for os in range(len(otherSearches)):                   
                        content += '<li><a href="/riscos/index?format='+otherSearches[os][1]+'&search='+otherSearches[os][2]+'">'+otherSearches[os][2]+'</a></li>'
                    #endfor
                    content += '</ul>'
                #endif
            #endif
            content += '</div>'
        #endif
        content += self.footer()
        return content
    #enddef
    
    def embed_web_sites(self, docIds):
        content = ""
        distinctUrls = []
        for docId in docIds:
            document = self.riscosCollection.find_one({'_id':ObjectId(docId),"application_directory":{"$exists":True,"$ne":""},"parent_url":{"$exists":True,"$ne":""}})
            if document and not document['parent_url'] in distinctUrls:
                distinctUrls.append(document['parent_url'])
            #endif
        #endfor
        distinctUrls.sort()
        for distinctUrl in distinctUrls:
            distinctApps = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""},"parent_url":distinctUrl}).distinct("application_directory")
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
                    count = self.riscosCollection.find({'_id':ObjectId(doc_id),'relocatable_modules_dependant_upon.name':'UtilityModule'}).count()
                    if count:
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id),'relocatable_modules_dependant_upon.name':'UtilityModule'})
                        for item in document['relocatable_modules_dependant_upon']:
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
                    count = self.riscosCollection.find({'_id':ObjectId(doc_id),'relocatable_modules.addressing_mode':{"$exists":True}}).count()
                    if count:
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
                    count = self.riscosCollection.find({'_id':ObjectId(doc_id),'relocatable_modules_dependant_upon.name':'UtilityModule'}).count()
                    if count:
                        document = self.riscosCollection.find_one({'_id':ObjectId(doc_id),'relocatable_modules_dependant_upon.name':'UtilityModule'})
                        for item in document['relocatable_modules_dependant_upon']:
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
                    count = self.riscosCollection.find({'_id':ObjectId(doc_id),'relocatable_modules.addressing_mode':{"$exists":True}}).count()
                    if count:
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
                            if document.has_key('last_modified') and document['last_modified']:
                                try:
                                    documentYear = int(time.ctime(int(document['last_modified']))[-4:])
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
                    filteredDocIds.append(doc_id)
                #endif
            #endfor
        else:
            filteredDocIds = doc_ids
        #endif    
        return filteredDocIds
    #endif
    
    @cherrypy.expose
    def advanced(self, attribute='application_directory', value='', nested=False, removal=False, spider=False):
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
                    userDocument['basket'] = []
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
                content += '<tr><th>'+key+'</th><td>'+userDocument['search_criteria'][key]+'</td><td><form class="inline" action="/riscos/remove_search_component" method="post"><input type="hidden" name="attribute" value="'+key+'"><input type="hidden" name="value" value="'+userDocument['search_criteria'][key]+'"><input class="basket" type="submit" value="Remove"></form></td></tr>'
            #endfor
            content += '</tbody></table>'
        #endif
        
        content += '<p><form action="/riscos/advanced" method="post">'
        
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
                        if attribute in ['relocatable_modules','relocatable_modules_dependant_upon','utilities']:
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
                        if attributeToSearch in ['relocatable_modules','relocatable_modules_dependant_upon','utilities']:
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
                content += self.display_document_table(filteredDocIds, 'advanced', nested)
            else:
                content += self.display_document_report(filteredDocIds, 'advanced', nested)
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
                    if document.has_key('application_directory') and document['application_directory']:
                        if not document.has_key('superseded_by') or not document['superseded_by']:
                            filteredDocIds.append(doc_id)
                        #endif
                    #endif            
                #endif
            #endfor
            for doc_id in doc_ids:
                document = self.riscosCollection.find_one({'_id':ObjectId(doc_id)})
                if document:
                    if document.has_key('application_directory') and document['application_directory']:
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
                    if not (document.has_key('application_directory') and document['application_directory']):
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
                    if not (document.has_key('application_directory') and document['application_directory']):
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
                            content += '<th valign="bottom" align="center">'
                            if image:
                                content += '<img src="/riscos/images/'+image+'" alt="'+image+'">'
                            #endif
                            content += '</th>'
                        #endif
                    #endfor
                    content += '<th></th></tr>'

                    content += '<tr>'
                    for (externalAttribute,internalAttribute,image) in self.displayedAttributes:
                        if internalAttribute in columnsRequired:
                            content += '<th>'+externalAttribute+'</th>'
                        #endif
                    #endfor
                    content += '<th>Buttons</th></tr>'

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
                                    
                                elif internalAttribute == 'application_name':        
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><b>'+document[internalAttribute]+'</b></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
                                    
                                elif internalAttribute == 'application_version':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        if document.has_key('superseded_by') and document['superseded_by']:
                                            count = self.riscosCollection.find({'_id':ObjectId(document['superseded_by'])}).count()
                                            if count:
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
                                        
                                elif internalAttribute == 'last_modified':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        try:
                                            timeString = time.ctime(int(document['last_modified']))
                                            content += '<td valign="top">'+timeString+'</td>'
                                        except:
                                            content += '<td valign="top">'+document[internalAttribute]+'</td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
                                        
                                elif internalAttribute == 'last_scanned':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        timeString = time.ctime(int(document['last_scanned']))
                                        content += '<td valign="top">'+timeString
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
                                        content += 'In '+str(noOfDays)+' Days<br><sub>' + timeString+'</sub><br>'
                                    #endif
                                    # If document is over a year old, provide a 'Rescan' button
                                    if document.has_key('last_scanned') and epoch-31536000 > document['last_scanned']:
                                        if userDocument and ((userDocument.has_key('rescan_count') and userDocument['rescan_count'] < 10) or (not userDocument.has_key('rescan_count'))):
                                            content += '<form class="inline" action="/riscos/rescan" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input type="hidden" name="origin" value="'+origin+'"><input class="rescan" type="submit" value="Rescan" title="Mark the document to be rescanned at the next opportunity"></form>'
                                        #endif
                                    #endif
                                    content += '</td>'
                                        
                                elif internalAttribute == 'url':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        if document[internalAttribute].lower().endswith('.zip'):
                                            if document.has_key('zip_file') and not document[internalAttribute].lower().__contains__('/softwareunconfirmed/'):
                                                if document.has_key('application_name') and document['application_name']:
                                                    title = "Download "+document['application_name']
                                                elif document.has_key('application_directory') and document['application_directory']:
                                                    title = "Download "+document['application_directory']
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
                                    
                                elif internalAttribute == 'parent_url':
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td align="center" valign="top"><a href="'+document[internalAttribute]+'" target="_blank" title="'+document[internalAttribute]+'"><img src="/riscos/images/url.gif"></a></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif
        
                                elif internalAttribute in ['minimum_riscos_versions']:
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
                                    
                                    #elif internalAttribute == 'relocatable_modules_dependant_upon':
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
                                        helpText = helpText.replace('RISC-OS','RISC OS')
                                        helpText = helpText.replace('Risc Os','RISC OS')
                                        helpText = helpText.replace('<','&lt;')
                                        helpText = helpText.replace('>','&gt;')
                                        content += '<td valign="top"><textarea rows="10" cols="40" readonly>'+helpText+'</textarea></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif

                                elif internalAttribute in ['programming_languages']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:
                                            content += '<li>'+item.replace(' ','&nbsp;')+'</li>'
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
                                    
                                elif internalAttribute in ['absolutes','categories','dtp_formats','filetypes_read','fonts','monitor_definition_files','territories','system_variables']:
                                    if document.has_key(internalAttribute) and document[internalAttribute]:
                                        content += '<td valign="top"><ul>'
                                        for item in document[internalAttribute]:
                                            content += '<li>'+item+'</li>'
                                        #endfor
                                        content += '</ul></td>'
                                    else:
                                        content += '<td></td>'
                                    #endif                                
        
                                elif internalAttribute in ['relocatable_modules','utilities']:
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
                                                        content += '<td>'+str(subDocument[columnDBField])+'</td>'
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
        
                                elif internalAttribute in ['relocatable_modules_dependant_upon']:
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
                        
                        if userDocument.has_key('basket') and str(document['_id']) in userDocument['basket']:
                            content += '<form class="inline" action="/riscos/remove_from_basket" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input type="hidden" name="origin" value="'+origin+'">'
                            if nested:
                                content += '<input type="hidden" name="nested" value="true">'
                            #endif                     
                            content += '<input class="basket" type="submit" value="Remove" title="Remove from basket"></form>'
                        else:
                            content += '<form class="inline" action="/riscos/add_to_basket" method="post"><input type="hidden" name="doc_id" value="'+str(document['_id'])+'"><input type="hidden" name="origin" value="'+origin+'">'
                            if nested:
                                content += '<input type="hidden" name="nested" value="true">'
                            #endif
                            content += '<input class="basket" type="submit" value="Add" title="Add to basket"></form>'
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
                            if (document.has_key('application_directory') and document['application_directory']) or (document.has_key('application_name') and document['application_name']):
                                if document.has_key('application_directory') and document['application_directory'] and document.has_key('application_name') and document['application_name']:
                                    content += '<p class="report"><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_name']+'</a> ('+document['application_directory']+')'+self.insert_application_version_and_or_date(document)+self.insert_last_modified_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                elif document.has_key('application_directory') and document['application_directory']:
                                    content += '<p class="report"><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_directory']+'</a>'+self.insert_application_version_and_or_date(document)+self.insert_last_modified_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                elif document.has_key('application_name') and document['application_name']:
                                    content += '<p class="report"><a class="external" href="'+document['url']+'" target="_blank" title="'+document['url']+'"><img src="/riscos/images/ddc.png" border="0"> '+document['application_name']+'</a>'+self.insert_application_version_and_or_date(document)+self.insert_last_modified_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
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
                                    content += '<p class="report">'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+self.insert_last_modified_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                                else:
                                    content += '<p class="report">'+document['embed']+'<br><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['url']+'</a>'+self.insert_parent_hyperlink(document)+self.insert_last_modified_date(document)
                                #endif
                            elif document.has_key('page_title') and document['page_title']:
                                content += '<p class="report"><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['page_title']+'</a>'+self.insert_last_modified_date(document)+'<br><b class="green">'+document['url']+self.insert_parent_hyperlink(document)+'</b>'
                            else:   
                                content += '<p class="report"><a href="'+document['url']+'" target="_blank" title="'+document['url']+'">'+document['url']+'</a>'+self.insert_parent_hyperlink(document)+self.insert_last_modified_date(document)
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
                content += ' '+document['application_version']+' ('+document['date']+')'
            elif document.has_key('application_version') and document['application_version']:
                content += ' '+document['application_version']
            elif document.has_key('date') and document['date']:
                content += ' ('+document['date']+')'
            #endif
        #endif
        return content
    #enddef    
    
    def insert_last_modified_date(self,document):
        content = ""
        if document.has_key('last_modified') and document['last_modified']:
            try:
                timeString = time.ctime(int(document['last_modified']))
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
    def database(self, nested=False):
        status = self.cookie_handling()
        content = ""
        port = ""
        content += self.header(status, 'noindex, follow')
        if self.mongodbPort != 27017:
            port = ' --port '+str(self.mongodbPort)
        #endif
        executable = r'"C:\Program Files\MongoDB\bin\mongodump.exe" --verbose'+port+' --db riscos --out '+self.path+os.sep+'dbdump'
        (status,output) = self.getstatusoutput(executable)
        content += '<p>The entire MongoDB Database in BSON/JSON format is available upon request.</p>'
        content += '<p>Certain extracts in JSON or CSV format are available to download from the footer.</p>'
        content += '</div></body>'
        content += self.footer()
        return content  
    #enddef

    @cherrypy.expose
    def csv(self, nested=False):
        status = self.cookie_handling()
        content = ""
        port = ""
        content += self.header(status, 'noindex, follow')
        if self.mongodbPort != 27017:
            port = ' --port '+str(self.mongodbPort)
        #endif
        executable = r'"C:\Program Files\MongoDB\bin\mongoexport.exe" --verbose'+port+' --db riscos --collection riscos --csv -f application_name,application_directory,application_version,date,purpose,description,filetypes_read,filetypes_set,absolutes,utilities,relocatable_modules,relocatable_modules_dependant_upon,programming_languages,fonts,help,dtp_formats,minimum_riscos_versions,monitor_definition_files,printer_definition_files,star_commands,system_variables,territories,source,author,copyright,license,package_name,package_section,package_version,categories,maintainer,priority,page_title,url,parent_url,last_modified,last_scanned,next_scan --out '+self.path+os.sep+'downloads'+os.sep+'riscos.csv'
        (status,output) = self.getstatusoutput(executable)
        content += '<p><a href="/riscos/downloads/riscos.csv">Download Database in CSV Format</p>'
        content += '</div></body>'
        content += self.footer()
        return content  
    #enddef  
    
    @cherrypy.expose
    def json(self, nested=False):
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
    def latestapps(self):
        status = self.cookie_handling()
        content = ""
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += self.header(status, 'index, nofollow')
        content += '<h2>Latest Apps</h2>'   
        doc_ids = []
        localTime = time.localtime(int(time.time()))
        year = localTime[0]
        while year >= 1987:
            for month in ['Dec','Nov','Oct','Sep','Aug','Jul','Jun','May','Apr','Mar','Feb','Jan']:
                for date in ['31','30','29','28','27','26','25','24','23','22','21','20','19','18','17','16','15','14','13','12','11','10','09','08','07','06','05','04','03','02','01']:
                    regex = re.compile(date+'[ -]'+month+'[ -]'+str(year))
                    subset_doc_ids = self.riscosCollection.find({'date':regex}).distinct('_id')
                    for subset_doc_id in subset_doc_ids:
                        doc_ids.append(subset_doc_id)
                    #endfor
                    if len(doc_ids) >= 10:
                        break
                    #endif
                #endfor
                if len(doc_ids) >= 10:
                    break
                #endif
            #endfor
            if len(doc_ids) >= 10:
                break
            else:
                year -= 1
            #endif
        #endwhile
        content += self.display_document_report(doc_ids, 'news', False)
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def news(self):
        epoch = int(time.time())
        status = self.cookie_handling()
        content = ""
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        content += self.header(status, 'index, nofollow')
        content += '<h2>News</h2>'    
        content += '<p>An amalgamation of RSS Feeds upto 28 days old from around the World Wide Web</p>'
        for document in self.urlsCollection.find({'rss_feed_item_date':{'$gt':epoch-2419200}}):
            content += '<p>'
            if document.has_key('rss_feed_item_title') and document['rss_feed_item_title']:
                content += '<b>'+document['rss_feed_item_title']+'<b><br>'
            #endif
            if document.has_key('rss_feed_item_description') and document['rss_feed_item_description']:
                content += document['rss_feed_item_description']+'<br>'
            #endif
            if document.has_key('rss_feed_item_link') and document['rss_feed_item_link']:
                content += '<a href="'+document['rss_feed_item_link']+'">'+Link+''
            #endif
            content += '</p>'
        #endfor
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def latest_records(self):
        status = self.cookie_handling()
        content = ""
        userDocument = self.usersCollection.find_one({"session_id":self.sessionId})
        epoch = int(time.time())
        content += self.header(status, 'noindex, follow')
        
        content += '<h2>Latest Records</h2>'
            
        # Gather records last modified in the past N days (upto a max of 28 days) in steps of 1 day
        for timePeriod in xrange(86400,2419200,86400):
            lastModifieds = self.riscosCollection.find({'last_modified':{'$gte':epoch-timePeriod}}).distinct('last_modified')
            lastModifieds.sort(reverse=True)
            
            doc_ids = []
            for lastModified in lastModifieds:
                # Ensure last_modified and last_scanned dates are at least two hours apart
                subset_doc_ids = self.riscosCollection.find({'last_modified':lastModified,'last_scanned':{'$gt':lastModified+7200}}).distinct('_id')
                for subset_doc_id in subset_doc_ids:
                    doc_ids.append(subset_doc_id)
                #endfor
            #endfor
            if len(doc_ids) >= 32:
                break
            #endif
        #endfor
        if userDocument and userDocument.has_key('view') and userDocument['view'] and userDocument['view'] == 'table':
            content += self.display_document_table(doc_ids, 'index', False)
        else:
            content += self.display_document_report(doc_ids, 'index', False)
        #endif
        content += self.footer()
        return content
    #enddef

    @cherrypy.expose
    def how_can_you_help(self):
        epoch = int(time.time())
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, follow')
        
        content += '<h2>How Can You Help</h2>'
        
        content += '<div id="introduction">'
        
        content += '<h3 class="introduction">Submit a URL</h3>'
        
        content += '<p class="introduction">Should you come across a URL that you believe we have not scanned yet, please feel free to submit it to us just in case it is not on the backlog waiting to be processed. Should you create a brand new RISC OS-related web site, please feel free to submit its home page and we will spider our way to the rest.</p>'
        
        content += '<h3 class="introduction">ZIP File Format</h3>'
        
        content += '<p class="introduction">Should you host legacy .zip files on your own website, ensure that they have been resaved in the more modern .zip file format.</p>'
        
        content += '<h3 class="introduction">Blacklist</h3>'
        
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
        content += '<ul><li>Windows or Linux computer</li><li>Python 2.7x</li><li>MongoDB  (NoSQL database management system)</li><li>pymongo (Python-based library for MongoDB)</li></ul></p>'
        
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
        content += '<p class="introduction">Welcome to The RISC OS Search Engine, a completely automated web site primarily dedicated to finding and cataloguing software for the Reduced Instruction Set Computing Operating System (RISC OS) originally developed by Acorn Computers.</p>'
        content += '<p class="introduction">As you read this, our Search Engine is spidering around the World Wide Web basically looking for RISC OS-related web sites containing .zip files. Upon finding such a file, its contents will be analysed and information about the RISC OS Software it contains will be extracted and stored in our Database. Along the way, we also search for and collate the contents of riscos.xml files, capture the title of each HTML page and make a note of any Spark or Arc files we encounter.</p>'
        content += '<p class="introduction">For RISC OS users without a suitable decompression application to unpack archive files, SparkPlug is available as a <a href="http://www.davidpilling.net/splug.bas">self-extracting archive</a>. Once downloaded, just set its filetype to \'BASIC\' and double-click on it to create the !SparkPlug application.</p>'
        content += '<p class="introduction">It should be noted that not all RISC OS Software will be found via The RISC OS Search Engine as we may be prevented from indexing a zip file due to settings in robots.txt and any knowledge we have of commercial RISC OS Software comes to us by way of riscos.xml files so we\'re completely at the mercy of the developers!</p>'
        content += '<p class="introduction">The RISC OS Search Engine is being developed by Rebecca Shalfield for "The RISC OS Community" and as a potential partner for the RISC OS Packaging Project.</p>'
        content += '<p class="introduction">Disclaimer: As we are currently unable to completely identify whether RISC OS Software downloadable via this web site will actually run on your particular version of RISC OS, the downloading and installation of any such Software is entirely at your own risk!</p>'
        content += '<p class="introduction">The RISC OS Search Engine is primarily collating links to external web sites and RISC OS Software. No RISC OS Software is directly downloadable from the computer hosting The RISC OS Search Engine except that explicitly added by an individual hosting a mirror, such as the products of Cherisha Software.</p>'
        content += '<p class="introduction">As this web site\'s three Python source code files and the entire contents of our Database are being made freely available to "The RISC OS Community", please feel free to use in any way you wish for the good of "The RISC OS Community" just so long as you don\'t make a profit!</p>'
        content += '<p class="introduction">We actively encourage this RISC OS Search Engine web site in its entirety to be cloned and mirrored throughout the Internet. It is envisaged that this RISC OS Search Engine @ '+self.mirror+' will be just one of many, all sharing data between them!</p>'
        
        try:
            # Returns all riscos plus rejects documents scanned in the last 28 days
            riscosCount = self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-2419200}}).count()
            rejectsCount = self.rejectsCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-2419200}}).count()
            urlsCount = self.urlsCollection.find({'url':{'$ne':['']}}).count()
            content += '<p class="introduction">We are averaging '+str(int((riscosCount+rejectsCount)/28))+' URL scans a day; it will therefore take us '+str(int(urlsCount/((riscosCount+rejectsCount)/28)))+' days to plough through the backlog!</p>'
        except:
            True
        
        content += '<p class="introduction">This web site is undergoing regular development as at 2nd November 2013.</p>'
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
                #endif
            #endif
            userDocument["last_visit"] = epoch
            self.usersCollection.save(userDocument)
        #endif

        content += '<h2>Application Search</h2>'
        
        if not search:
            distinctApps = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""}}).distinct("application_directory")
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

        if search:
            if format == 'string':
                search = re.escape(search)
            #endif
            doc_ids = []
            attributesToSearch = ['application_name','application_directory']
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
            attributesToSearch = ['filetypes_set','filetypes_read']
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
            #endif
        #endif
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
            #endif
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
                    userDocument['basket'] = []
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
            doc_ids = []
            attributesToSearch = ['glossary_term']
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
            #endif
        #endif
        content += self.footer()
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
                    userDocument['basket'] = []
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
                content += self.display_document_table(filteredDocIds, 'index', False)
            else:
                content += self.display_document_report(filteredDocIds, 'index', False)
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
    def reports(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, follow')
        content += '<h2>Reports</h2>'
        content += '<p><form class="inline" action="/riscos/badzipfiles" method="post"><input class="button" type="submit" value="Bad Zip Files"></form> <form class="inline" action="/riscos/filetypes" method="post"><input class="button" type="submit" value="Filetypes"></form> <form class="inline" action="/riscos/latest_records" method="post"><input class="button" type="submit" value="Latest Records"></form> <form class="inline" action="/riscos/riscos_xml_urls" method="post"><input class="button" type="submit" value="riscos.xml URLs"></form> <form class="inline" action="/riscos/rss_feeds" method="post"><input class="button" type="submit" value="RSS Feeds"></form></p>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def riscos_xml_scheme(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, nofollow')
        content += '<h2>The riscos.xml Scheme</h2>'
        content += '<div id="introduction">'
        content += '<p class="introduction">The RISC OS Search Engine fully supports the riscos.xml scheme.</p>'
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
        
        content += '<p class="introduction">Although the overall structure of a riscos.xml file is quite complex, you only have to include those sections applicable for your needs:</p>'
        format = '''
<?xml version="1.0" encoding="ISO-8859-1"?>
<riscos>
    <dealers>
        <dealer>
            <address>?</address>
            <description>?</description>
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
            <description>?</description>
            <email>?</email>
            <name>?</name>
            <telephone>?</telephone>
            <url>?</url>
        </developer>
        ...
    </developers>
    <events>
        <event>
            <date day="?" month="?" year="?"/>
            <description>?</description>
            <title>?</title>
            <url>?</url>
        </event>
        ...
    </events>
    <forums>
       <forum>
           <name>?</name>
           <description>?</description>
           <url></url>
       </forum>
       ...
    </forums>
    <glossary>
        <entry>
            <term>?</term>
            <definition>?</definition>
            <image url="?" caption="?" />
        </entry>
        ...
    </glossary>
    <hardware>
        <computers>
            <computer>
               <developer>?</developer>
               <description>?</description>
               <name>?</name>
               <url>?</url>
            </computer>
            ...
        </computers>
        <podules>
            <podule>
               <developer>?</developer>
               <description>?</description>
               <name>?</name>
               <url>?</url>
            </podule>
            ...
        </podules>
    </hardware>
    <publications>
        <books>
            <book>
                <description>?</description>
                <identifier>?</identifier>
                <price currency="?">?</price>
                <publisher>?</publisher>
                <title>?</title>
                <url>?</url>
            </book>
            ...
        </books>
        <magazines>
            <magazine>
                <description>?</description>
                <identifier>?</identifier>
                <price currency="?">?</price>
                <publisher>?</publisher>
                <title>?</title>
                <url>?</url>
            </magazine>
            ...
        </magazines> 
    </publications>
    <services>
        <service>
            <address>?</address>
            <category>?<category>
            <description>?</description>
            <email>?</email>
            <name>?</name>
            <telephone>?</telephone>
            <url>?</url>
        </service>
        ...
    </services>
    <software>
        <absolutes>
            <absolute>
               <name>?</name>
               <url>?</url>
            </absolute>
            ...
        </absolutes>
        <apps>
            <app>
                <author>?</author>
                <copyright>?</copyright>
                <released day="?" month="?" year="?"/>
                <description>?</description>
                <developer>?</developer>
                <directory>?</directory>
                <license>?</license>
                <maintainer>?</maintainer>
                <name>?</name>
                <url>?</url>
                <price currency="?">?</price>
                <programming_languages>?</programming_languages>
                <purpose>?</purpose>
                <system_variables>?</system_variables>
                <territories>?</territories>
                <version>?</version>
            </app>
            ...
        </apps>
        <fonts>
           <font>
               <name>?</name>
               <url>?</url>
           </font>
           ...
        </fonts>
        <relocatable_modules>
            <relocatable_module>
                <addressing_mode>?</addressing_mode>
                <name>?</name>
                <url>?</url>
                <version>?</version>
            </relocatable_module>
            ...
        </relocatable_modules>
        <monitor_definition_files>
            <monitor_definition_file>
                <monitor>?</monitor>
                <url>?</url>
            </monitor_definition_file>
            ...
        </monitor_definition_files>
        <printer_definition_files>
            <printer_definition_file>
                <printer>?</printer>
                <url>?</url>
            </printer_definition_file>
            ...
        </printer_definition_files>
        <utilities>
            <utility>
                <name>?</name>
                <url>?</url>
                <version>?</version>
            </utility>
            ...
        </utilities>
    </software>
    <usergroups>
        <usergroup>
            <address>?</address>
            <description>?</description>
            <email>?</email>
            <name>?</name>
            <telephone>?</telephone>
            <url>?</url>
        </usergroup>
        ...
    </usergroups>
    <videos>
        <video>
            <description>?</description>
            <title>?</title>
            <url>?</url>
        </video>
        ...
    </videos>
</riscos>
'''
        modifiedFormat = format.replace('<','&lt;')
        modifiedFormat = modifiedFormat.replace('>','&gt;')
        content += '<p><textarea rows="20" cols="70" readonly>'+modifiedFormat+'</textarea></p>'
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
        content += '<table class="software"><tr><th>riscos.xml Files</th></tr>'
        for i in range(len(riscosXmlFiles)):
            content += '<tr><td>'+str(i+1)+'</td><td>'+riscosXmlFiles[i]+'</td></tr>'
        #endfor
        content += '</table>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def badzipfiles(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'noindex, follow')
        content += '<h2>Bad Zip Files</h2>'
        content += '<p>The following .zip files are possibly in a legacy zip format not able to be decompressed by modern software</p>'
        badZipFiles = self.riscosCollection.find({'zip_file':{'$exists':True},'error':'Bad Zip File'}).distinct('zip_file')
        badZipFiles.sort()
        content += '<table class="software"><tr><th>Bad Zip Files</th></tr>'
        for i in range(len(badZipFiles)):
            content += '<tr><td>'+str(i+1)+'</td><td>'+badZipFiles[i]+'</td></tr>'
        #endfor
        content += '</table>'
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def rss_feeds(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'index, follow')
        content += '<h2>RSS Feeds</h2>'
        rssFeeds = self.riscosCollection.find({'rss_feed':{'$exists':True,'$ne':""}}).distinct('rss_feed')
        if rssFeeds:
            content += '<ul>'
            rssFeeds.sort()
            for rssFeed in rssFeeds:
                content += '<li><a href="'+rssFeed+'" target="_blank">'+rssFeed+'</a></li>'
            #endfor
            content += '</ul>'
        #endif
        content += self.footer()
        return content
    #enddef
    
    @cherrypy.expose
    def synchronise(self):
        content = ""
        if cherrypy.request.remote.ip in ['84.92.157.78', '192.168.15.100']:
            epoch = int(time.time())
            # Returns all riscos documents scanned in the last 48 hours
            count = self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-172800}}).count()
            content += "I have "+str(count)+" documents to send to you!"
        else:
            raise cherrypy.HTTPError("401 Unauthorised")
        #endif
        return content
    #enddef

    @cherrypy.expose
    def statistics(self):
        status = self.cookie_handling()
        content = ""
        content += self.header(status, 'noindex, follow')
        content += '<h2>Statistics</h2>'

        rows = [('Absolutes','absolutes','list','ff8.png',{'absolutes':{"$exists":True,"$nin":["",[]]}}),
                ('Apps','application_directory','string','app.png',{'application_directory':{"$exists":True,"$nin":["",[]]}}),
                ('ARC Files','arc_file','string','',{'arc_file':{"$exists":True,"$nin":["",[]]}}),
                ('Authors','author','string','',{'author':{"$exists":True,"$nin":["",[]]}}),
                ('Dealers','dealer','string','',{'dealer':{"$exists":True,"$nin":["",[]]}}),
                ('Developers','developer','string','',{'developer':{"$exists":True,"$nin":["",[]]}}),
                ('Filetypes','filetypes_read','list','',{'filetypes_read':{"$exists":True,"$nin":["",[]]}}),
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
                ('* Commands','star_commands','list','',{'star_commands':{"$exists":True,"$nin":["",[]]}}),
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
        for field in ['filetypes_set','filetypes_read']:
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
        content += '<table class="software"><tr><th>Hex</th><th>Textual</th></tr>'
        for (hex,textual) in filetypes:
            content += '<tr><td><a href="/riscos/filetype?search='+hex+'">'+hex+'</a></td><td><a href="/riscos/filetype?search='+textual+'">'+textual+'</a></td></tr>'
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
            content += '<tr><td>'+remoteUserAgent+'</td><td>'+str(count)+'</td></tr>'
        #endfor
        content += '</table></div></body>'
        content += self.footer()
        return content
    #enddef
    
    def footer(self):
        content = "</div>"
        epoch = int(time.time())
        
        # Get count of all URLs still to be spidered
        unprocessedUrlCount = self.urlsCollection.find().count()
        rejectedCount = self.rejectsCollection.find().count()
        reservedCount = self.reservesCollection.find().count()
        # Get count of all current URLs less than a year old
        processedUrlCount = self.riscosCollection.find({'url':{'$ne':['']},'last_scanned':{'$gte':epoch-31536000}}).count()
        
        noOfMembers = len(self.usersCollection.find({"username":{"$exists":True,"$ne":""}}).distinct("username")) 
        visitorsTodayCount = self.usersCollection.find({"session_id":{"$exists":True,"$ne":""},'last_visit':{'$gte':epoch-86400}}).count()
        membersTodayCount = len(self.usersCollection.find({"session_id":{"$exists":True,"$ne":""},"logged_on":{"$exists":True,"$ne":""},'last_visit':{'$gte':epoch-86400}}).distinct("logged_on"))
        guestsTodayCount = visitorsTodayCount - membersTodayCount
        
        content += '<div id="footer_container">'
        content += '<div id="footer_contents"><form class="inline" action="/riscos/riscos_xml_scheme" method="post"><input class="button" type="submit" value="riscos.xml Scheme"></form> | <form class="inline" action="/riscos/submit_url" method="post"><input type="text" name="url"> <input class="button" type="submit" value="Submit URL"></form> | <form class="inline" action="/riscos/how_can_you_help" method="post"><input class="button" type="submit" value="How Can You Help" title="How Can You Help"></form> <form class="inline" action="/riscos/statistics" method="post"><input class="button" type="submit" value="Statistics"></form> <form class="inline" action="/riscos/key" method="post"><input class="button" type="submit" value="Key"></form> <form class="inline" action="/riscos/visitors" method="post"><input class="button" type="submit" value="Visitors"></form> <form class="inline" action="/riscos/sourcecode" method="post"><input class="button" type="submit" value="Source Code"></form> <form class="inline" action="/riscos/database" method="post"><input class="button" type="submit" value="Database"></form> <form class="inline" action="/riscos/json" method="post"><input class="button" type="submit" value="JSON"></form> <form class="inline" action="/riscos/csv" method="post"><input class="button" type="submit" value="CSV"></form><br>'
        content += 'Copyright &copy; Rebecca Shalfield 2002-2013 | <a href="mail:rebecca.shalfield@shalfield.com">Contact Us</a>'
        content += ' | Processed URLs: '+str(processedUrlCount)+' | Unprocessed URLs: '+str(unprocessedUrlCount)+' | Reserved URLs: '+str(reservedCount)+' | Rejected URLs: '+str(rejectedCount)
        content += ' | No. of Members: '+str(noOfMembers)+' |  Guests Today: '+str(guestsTodayCount)+' |  Members Today: '+str(membersTodayCount)+'</div>'
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
            distinctApps = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""}}).distinct("application_directory")
            for distinctApp in distinctApps:
                if distinctApp.lower().startswith(term.lower()):
                    matches.append(distinctApp)
                #endif            
            #endfor            
        else:
            for attribute in ['application_directory','application_name']:
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
            for attribute in ['application_directory','application_name']:
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
        for attribute in ['filetypes_set','filetypes_read']:
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
            for attribute in ['filetypes_set','filetypes_read']:
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
        for attribute in ['relocatable_modules.name','relocatable_modules_dependant_upon.name']:
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
            for attribute in ['relocatable_modules.name','relocatable_modules_dependant_upon.name']:
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
            distinctApps = self.riscosCollection.find({"application_directory":{"$exists":True,"$ne":""}}).distinct("application_directory")
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
         '/softwareconfirmed'     : { 'tools.staticdir.on'      : True,
                           'tools.staticdir.dir'       : 'softwareconfirmed'
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
