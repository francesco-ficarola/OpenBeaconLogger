OpenBeacon Logger
=================

The OpenBeacon Logger is a software able to receive packets from [OpenBeacon Ethernet EasyReader PoE II - Active 2.4GHz RFID Reader](http://www.openbeacon.org/OpenBeacon_Ethernet_EasyReader_PoE_II_-_Active_2.4GHz_RFID_Reader) devices and store all messages on a log-file in order to be then parsed using the [OpenBeacon Log Parser](https://github.com/francesco-ficarola/OpenBeaconParser).

Author: *Francesco Ficarola*

How to compile
--------------

    $ mvn clean package assembly:single

This process automatically cleans obsolete files and assembles a package ready-to-run.

How to run
----------

You have two alternatives:

* by running the automatic extractor/executor script (it automatically extracts the archive package in the target folder and runs the executor script):

        $ ./OpenBeaconLogger.sh

* by manually extracting the archive package and run the executor script:

        $ cd target/
        $ tar -xzvf OpenBeaconLogger.tar.gz
        $ cd OpenBeaconLogger/
        $ ./startup.sh

Log-files
---------

Two log-files will be created as soon as the logger's execution starts:

* logs/openbeaconlogger.log: information, warnings and errors
* logs/interactions.log: packets received from tags