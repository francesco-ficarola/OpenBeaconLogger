package it.uniroma1.dis.wsngroup.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Functions {
	
	public static short byteArraytoShort(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);
//		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.order(ByteOrder.BIG_ENDIAN); // it depends on the platform
		return buffer.getShort();
	}
	
	public static int byteArraytoInt(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);
//		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.order(ByteOrder.BIG_ENDIAN); // it depends on the platform
		return buffer.getInt();
	}
	
	public static long byteArraytoLong(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);
//		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.order(ByteOrder.BIG_ENDIAN); // it depends on the platform
		return buffer.getLong();
	}
	
	public static int crc16(byte[] data) {
		int mask = 0xFFFF;
		int crc = 0xFFFF;
		for (byte b : data) {
			short x = (short) (b & 0xFF);
			crc = (crc >> 8) | ((crc << 8) & mask);
	        crc = crc ^ x;
	        crc = crc ^ ((crc & 0xff) >> 4);
	        crc = crc ^ ((crc << 12) & mask);
	        crc = crc ^ (((crc & 0xff) << 5) & mask);
		}
		return crc;
	}
}
