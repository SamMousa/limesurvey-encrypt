limesurvey-encrypt
==================

Plugin for limesurvey that enables asymmetric response encryption.


Installation via GIT
====================

1. Open a terminal
2. Go to the plugins directory
3. Type git clone https://github.com/SamMousa/limesurvey-encrypt.git Encrypt


Installation from ZIP
=====================

1. Download the zip file here https://github.com/SamMousa/limesurvey-encrypt/archive/master.zip
2. Extract the files to the plugins/Encrypt directory.


Configuration
=============

1. Install
2. Create an OpenSSL key pair
3. Set public key at plugin settings
4. Enable / disable in survey settings, default is enabled

Exporting results
=================

1. Go to survey settings
2. If number of encrypted responses is > 0 there will be an export button.
3. Save the file to a directory where decrypt.php and your private key are located. (must be named key.priv)
4. Open a terminal in that directory.
5. Execute php decrypt.php > data.csv 

