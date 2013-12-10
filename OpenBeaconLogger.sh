#!/bin/bash
cd target/
if [ ! -d "OpenBeaconLogger" ]; then
	tar -xzf OpenBeaconLogger.tar.gz
fi
cd OpenBeaconLogger/
./startup.sh $1
