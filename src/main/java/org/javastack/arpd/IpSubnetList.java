package org.javastack.arpd;

public class IpSubnetList {
	private static final int MAX_ELEMENTS = 4096;
	private int[] address = new int[MAX_ELEMENTS];
	private byte[] bits = new byte[MAX_ELEMENTS];
	private int current = 0;

	public void add(String netAddress) {
		final int p = netAddress.indexOf('/');
		address[current] = getIPFromString((p == -1) ? netAddress : netAddress.substring(0, p));
		bits[current] = ((p == -1) ? 32 : Byte.parseByte(netAddress.substring(p + 1)));
		current++;
	}

	public boolean contains(final String ip) {
		final int check = getIPFromString(ip);
		for (int i = 0; i < current; i++) {
			if (getNetworkPart(address[i], bits[i]) == getNetworkPart(check, bits[i])) {
				return true;
			}
		}
		return false;
	}

	public void clear() {
		current = 0;
	}

	/**
	 * Returns the network part of an ip address with the given fixed bits
	 * (fixed_bits is number of leading bits that are part of network address).
	 */
	public static int getNetworkPart(int ip, final int fixed_bits) {
		if ((fixed_bits == 32) || (fixed_bits == -1)) {
			return ip;
		}
		if ((fixed_bits < 0) || (fixed_bits > 32)) {
			throw new IllegalArgumentException("Bad number of fixed bits!");
		}
		// zero the least significant bits, and shift back into place
		ip >>= (32 - fixed_bits);
		ip <<= (32 - fixed_bits);
		return ip;
	}

	/** Returns if two IP addresses are in the same network of the specified size. */
	public static boolean inSameSubnet(final int ip1, final int ip2, final int fixed_bits) {
		final int network1 = getNetworkPart(ip1, fixed_bits);
		final int network2 = getNetworkPart(ip2, fixed_bits);
		return (network1 == network2);
	}

	/**
	 * Checks whether a string can be an IP address.
	 * 
	 * @param name the string to check
	 * @return true if it is an IP address, false otherwise
	 */
	public static boolean isIPString(final String name) {
		final String[] parts = name.split("\\.");
		if (parts.length != 4) {
			return false;
		}
		for (int i = 0; i < 4; i++) {
			int tmp = Integer.parseInt(parts[i]);
			if ((tmp < 0) || (tmp > 255)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Determines the ID of the Node by IP address string
	 * 
	 * @param name a dotted decimal IP address string
	 * @return the int representation of the specified IP; -1 if it cannot be parsed
	 */
	public static int getIPFromString(final String name) {
		if (!isIPString(name)) {
			return -1;
		}
		final String[] parts = name.split("\\.");
		int ip = 0;
		for (int i = 0; i < 4; i++) {
			final int tmp = Integer.parseInt(parts[i]);
			ip = ((ip << 8) | (tmp & 0xFF));
		}
		return ip;
	}

	/**
	 * Convert an 32-bit integer IP into a string.
	 * 
	 * @param ip the integer ip address
	 * @return the string representation of the IP
	 */
	public static String getStringFromIP(final int ip) {
		final StringBuilder sb = new StringBuilder();
		sb.append((ip >> 24) & 0xFF).append(".");
		sb.append((ip >> 16) & 0xFF).append(".");
		sb.append((ip >> 8) & 0xFF).append(".");
		sb.append(ip & 0xFF);
		return sb.toString();
	}
}
