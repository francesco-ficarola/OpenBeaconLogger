package it.uniroma1.dis.wsngroup.logging;

import it.uniroma1.dis.wsngroup.utils.Constants;
import it.uniroma1.dis.wsngroup.utils.Functions;
import it.uniroma1.dis.wsngroup.utils.XXTEA;

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
				//int eCrc = Functions.byteArraytoInt(new byte[] {0, 0, rawDataPacket[0], rawDataPacket[1]});
				//short eProto = Functions.byteArraytoShort(new byte[] {0, rawDataPacket[2]});
				//short eInterface = Functions.byteArraytoShort(new byte[] {0, rawDataPacket[3]});
				int eReaderID = Functions.byteArraytoInt(new byte[] {0, 0, rawDataPacket[4], rawDataPacket[5]});
				String eReaderIDHex = "0x" + String.format("%08x", eReaderID & 0xFFFFFFFF);
				int eSize = Functions.byteArraytoInt(new byte[] {0, 0, rawDataPacket[6], rawDataPacket[7]});
				long eSequence = Functions.byteArraytoLong(new byte[] {0, 0, 0, 0, rawDataPacket[8], rawDataPacket[9], rawDataPacket[10], rawDataPacket[11]});
				long eTimestamp = Functions.byteArraytoLong(new byte[] {0, 0, 0, 0, rawDataPacket[12], rawDataPacket[13], rawDataPacket[14], rawDataPacket[15]});
				logger.debug("Reader fields: " + "reader_id: " + eReaderIDHex + ", pkt size: " + eSize + ", reader_seq: " + eSequence + ", reader_ts: " + eTimestamp);
				
				/** Second 16th bytes - Payload encrypted by XXTEA */
				byte[] encryptedPayload = Arrays.copyOfRange(rawDataPacket, 16, rawDataPacket.length);
				logger.debug("Encrypted Payload: " + Arrays.toString(encryptedPayload));
				ByteBuffer byteBuffer = ByteBuffer.allocate(Constants.XXTEA_KEY.length * 4);
				for(int i=0; i<4; i++) {
					byteBuffer.putInt(Constants.XXTEA_KEY[i]);
				}
				byte[] key = byteBuffer.array();
				byte[] decryptedPayload = XXTEA.decrypt(encryptedPayload, key);				
				logger.debug("Decrypted payload: " + Arrays.toString(decryptedPayload));
				
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
					String idString = idInHex ? String.format("%04x", id & 0xFFFF) : String.valueOf(id);
					short flags = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[3]});
					
					/** Sighting Message (TBeaconTracker) */
					if(proto == 24) {
						short strength = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[4]});
						int idLastSeen = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[5], decryptedPayload[6]});
						String idLastSeenString = idInHex ? String.format("%04x", idLastSeen & 0xFFFF) : String.valueOf(idLastSeen);
						int bootCount = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[7], decryptedPayload[8]});
						short reserved = Functions.byteArraytoShort(new byte[] {0, decryptedPayload[9]});
						long seq = Functions.byteArraytoLong(new byte[] {0, 0, 0, 0, decryptedPayload[10], decryptedPayload[11], decryptedPayload[12], decryptedPayload[13]});
						String seqHex = "0x" + String.format("%08x", seq & 0xFFFFFFFF);
						
						String	msg = "S t=" + currentTimestamp + " ip=" + eReaderIDHex + " id=" + idString + " boot_count=" + bootCount + " seq=" + seqHex + " strgth=" + strength + " flgs=" + flags + " last_seen=" + idLastSeenString;
						LogInteraction.write(msg);
						logger.debug("[Sighting Message] proto: " + proto + ", id: " + idString + ", strength: " + strength + ", id_last_seen: " + idLastSeenString + ", boot_count: " + bootCount + ", reserved: " + reserved + ", seq: " + seqHex + ", crc: " + crc);
					}
					
					else
					
					/** Contact Message (TBeaconProx) */
					if(proto == 69) {
						int neighbor1 = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[4], decryptedPayload[5]});
						int neighbor2 = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[6], decryptedPayload[7]});
						int neighbor3 = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[8], decryptedPayload[9]});
						int neighbor4 = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[10], decryptedPayload[11]});
						int shortSeq = Functions.byteArraytoInt(new byte[] {0, 0, decryptedPayload[12], decryptedPayload[13]});
						String shortSeqHex = "0x" + String.format("%08x", shortSeq & 0xFFFFFFFF);
						
						int neighbors[] = {neighbor1, neighbor2, neighbor3, neighbor4};
						String neighbors_str = "";
						for (int neighbor : neighbors) {
							if(neighbor != 0) {
								String neighborIdStr = String.valueOf(neighbor & 0x0FFF);
								if(idInHex) {
									neighborIdStr = Integer.toHexString(neighbor & 0x0FFF);
								}
								int seenPower = neighbor >> 14;
								int seenCnt = (neighbor >> 12) & 0x03;
								neighbors_str += "[" + neighborIdStr + "(" + seenPower + ")" + " #" + seenCnt + "] ";
							}
						}
						
						String msg = new String("C t=" + currentTimestamp + " ip=" + eReaderIDHex + " id=" + idString + " boot_count=0" + " seq=" + shortSeqHex + " " + neighbors_str).trim();
						LogInteraction.write(msg);
						logger.debug("[Contact Message] proto: " + proto + ", id: " + idString + ", seq: " + shortSeqHex + ", neighbors: " + neighbors_str + ", crc: " + crc);
					}
					
				} else {
					logger.warn("Rejecting packet from " + eReaderIDHex + " on CRC.\n");
				}
				
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

}
