package it.uniroma1.dis.wsngroup.logging;

import it.uniroma1.dis.wsngroup.utils.Constants;
import it.uniroma1.dis.wsngroup.utils.Functions;
import it.uniroma1.dis.wsngroup.utils.XXTEA;

import java.awt.HeadlessException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.log4j.Logger;

/**
 * @author Francesco Ficarola
 *
 */

public class ReaderLogger {
	
	private Logger logger = Logger.getLogger(this.getClass());
	private DatagramSocket serverSocket;
	
	public ReaderLogger(DatagramSocket serverSocket) {
		this.serverSocket = serverSocket;
	}
	
	public void receivePackets(boolean idInHex) {
		byte[] receiveData = new byte[Constants.TAG_PACKET_SIZE];
		while(true) {
			DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
			long currentTimestamp = System.currentTimeMillis() / 1000L;
			
			try {
				serverSocket.receive(receivePacket);
				byte[] rawDataPacket = receivePacket.getData();
				logger.debug("Raw Data Packet: " + Arrays.toString(rawDataPacket));
				
				
				/**
				 * uint8_t (C) = short (java), uint16_t (C) = int (java), uint32_t (C) = long (java)
				 * Java needs double-sized primitives because they are all signed.
				 */
				
				/** First 16th bytes - Reader data */
				int eCrc = Functions.byteArraytoInt(new byte[] {0, 0, rawDataPacket[0], rawDataPacket[1]});
				short eProto = Functions.byteArraytoShort(new byte[] {0, rawDataPacket[2]});
				short eInterface = Functions.byteArraytoShort(new byte[] {0, rawDataPacket[3]});
				int eReaderID = Functions.byteArraytoInt(new byte[] {0, 0, rawDataPacket[4], rawDataPacket[5]});
				int eSize = Functions.byteArraytoInt(new byte[] {0, 0, rawDataPacket[6], rawDataPacket[7]});
				long eSequence = Functions.byteArraytoLong(new byte[] {0, 0, 0, 0, rawDataPacket[8], rawDataPacket[9], rawDataPacket[10], rawDataPacket[11]});
				long eTimestamp = Functions.byteArraytoLong(new byte[] {0, 0, 0, 0, rawDataPacket[12], rawDataPacket[13], rawDataPacket[14], rawDataPacket[15]});
				logger.info("Reader fields: " + eCrc + ", " + eProto + ", " + eInterface + ", " + eReaderID + ", " + eSize + ", " + eSequence + ", " + eTimestamp);
				
				/** Second 16th bytes - Payload encrypted by XXTEA */
				byte[] encryptedPayload = Arrays.copyOfRange(rawDataPacket, 16, rawDataPacket.length);
				logger.info("Encrypted Payload: " + Arrays.toString(encryptedPayload));
				ByteBuffer byteBuffer = ByteBuffer.allocate(Constants.XXTEA_KEY.length * 4);
				for(int i=0; i<4; i++) {
					byteBuffer.putInt(Constants.XXTEA_KEY[i]);
				}
				byte[] key = byteBuffer.array();
				byte[] decryptedPayload = XXTEA.decrypt(encryptedPayload, key);				
				logger.info("Decrypted payload: " + Arrays.toString(decryptedPayload));
				
				/**
				 * TBeaconTracker Message:				TBeaconProx Message:
				 * uint8_t proto;						uint8_t proto;
				 * uint16_t id;							uint16_t id;
				 * uint8_t flags;						uint8_t flags;
				 * uint8_t strength;					uint16_t neighbor1;
				 * uint16_t oid_last_seen;				uint16_t neighbor2;
				 * uint16_t powerup_count;				uint16_t neighbor3;
				 * uint8_t reserved;					uint16_t neighbor4;
				 * uint32_t seq;						uint16_t short_seq;
				 * uint16_t crc;						uint16_t crc;
				 */ 
				
				/** Checking packet CRC */
				int crc = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[14], decryptedPayload[15]});
				byte[] payloadWithoutCrc = Arrays.copyOfRange(decryptedPayload, 0, 14);
				
				if(Functions.crc16(payloadWithoutCrc) == crc) {
					
					/** Header */
					short proto = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[0]});
					int id = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[1], decryptedPayload[2]});
					short flags = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[3]});
					
					/** Sighting Message (TBeaconTracker) */
					if(proto == 24) {
						short strength = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[4]});
						int id_last_seen = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[5], decryptedPayload[6]});
						int boot_count = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[7], decryptedPayload[8]});
						short reserved = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[9]});
						long seq = Functions.byteArraytoLong(new byte[] {0, 0, 0, 0, decryptedPayload[10], decryptedPayload[11], decryptedPayload[12], decryptedPayload[13]});
						
						String msg = "";
						if(idInHex) {
							msg = "S t=" + currentTimestamp + " ip=" + Integer.toHexString(eReaderID) + " id=" + Integer.toHexString(id) + " boot_count=" + boot_count + " seq=" + Long.toHexString(seq) + " strgth=" + strength + " flgs=" + flags + " last_seen=" + Integer.toHexString(id_last_seen);
						} else {
							msg = "S t=" + currentTimestamp + " ip=" + Integer.toHexString(eReaderID) + " id=" + id + " boot_count=" + boot_count + " seq=" + Long.toHexString(seq) + " strgth=" + strength + " flgs=" + flags + " last_seen=" + id_last_seen;
						}
						LogInteraction.write(msg);
						logger.info("[Sighting Message] proto: " + proto + ", id: " + id + ", strength: " + strength + ", id_last_seen: " + id_last_seen + ", boot_count: " + boot_count + ", reserved: " + reserved + ", seq: " + Long.toHexString(seq).toUpperCase() + ", crc: " + crc);
					}
					
					else
					
					/** Contact Message (TBeaconProx) */
					if(proto == 69) {
						
					}
					
				} else {
					logger.warn("Rejecting packet from" + eReaderID + "on CRC.\n");
				}
				
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

}
