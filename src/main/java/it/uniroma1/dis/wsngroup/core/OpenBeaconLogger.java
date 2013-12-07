package it.uniroma1.dis.wsngroup.core;

import java.net.DatagramSocket;
import java.net.SocketException;

import it.uniroma1.dis.wsngroup.logging.ReaderLogger;
import it.uniroma1.dis.wsngroup.utils.Constants;

import org.apache.log4j.Logger;

/**
 * @author Francesco Ficarola
 *
 */

public class OpenBeaconLogger {
	
	private static Logger logger = Logger.getLogger(OpenBeaconLogger.class);
	private static boolean idInHex = false;
	
	public static void main(String[] args) {
		
		inputParameters(args);
		
		boolean initialized = false;
		DatagramSocket serverSocket = null;
		
		while(!initialized) {
			try {
				serverSocket = new DatagramSocket(Constants.UDP_SERVER_PORT);
				initialized = true;
				logger.info("UDP Server has been initialized.");
			} catch (SocketException e) {
				logger.error("UDP Server has not been initialized: " + e.getMessage(), e);
			}
		}
		
		if(initialized) {
			ReaderLogger readerLogger = new ReaderLogger(serverSocket);
			readerLogger.receivePackets(idInHex);
		}
	}

	private static void inputParameters(String[] args) {
		if(args.length > 0) {
			for(int i = 0; i < args.length; i++) {
				if(args[i].equals("-hex")) {
					idInHex = true;
				}
				
				else
					
				if(args[i].equals("-h") || args[i].equals("--help")) {
					usage();
					System.exit(0);
				}
				
				else
					
				if(args[i].matches(".+")) {
					;
				}
				
				else {
					usage();
					System.exit(0);
				}
			}
		}
	}
	
	private static void usage() {
		System.out.println("\nTARGET SPECIFICATION:");
		System.out.println("-h or --help: Getting this help.");
		System.out.println("-hex or --hexadecimal-id: Tags' IDs are in HEX.\n");
	}

}
