<html xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="2.0">
    <head>
        <title>riscos.xml</title>
        <link rel="stylesheet" href="hrttp://192.168.15.100/riscos/riscos.css" />
    </head>
    <body>
        <h1>RISCOS.XML As HTML Via RISCOS.XSL</h1>
        <h2>Applications</h2>
        <xsl:for-each select="/riscos/software/apps/app">
            <h3><xsl:value-of select="name" /></h3>
            <p>Version <xsl:value-of select="version" /></p>
            <p><xsl:value-of select="description" /></p>
        </xsl:for-each>
    </body>
</html>
