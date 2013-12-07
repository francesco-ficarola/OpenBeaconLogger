package it.uniroma1.dis.wsngroup.logging;

import org.apache.log4j.Logger;

public class LogInteraction {
	
	private static Logger logger = Logger.getLogger(LogInteraction.class);
		
	public static void write(String msg) {
		logger.info(msg);
	}
}
