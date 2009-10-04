package org.javastack.arpd;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;

import org.apache.log4j.Logger;

// export LIBS=jpcap-0.7/lib/
// java -Djava.library.path=$LIBS -cp $LIBS/jpcap.jar ARPD
//
// jpcap: https://web.archive.org/web/20090305095412/http://netresearch.ics.uci.edu/kfujii/jpcap/
// javadoc: https://web.archive.org/web/20090227060855/http://netresearch.ics.uci.edu/kfujii/jpcap/doc/javadoc/index.html
//
public class ARPD implements Runnable {
	private static final Logger log = Logger.getLogger("ARPD");
	// BPF filter for capturing any ARP packet
	private static final String FILTER = "arp";
	private static final String EXCLUDE = ":exclude";
	private static final String INCLUDE = ":include";

	private static final String TEST_MODE_PROP = "arpd.test";
	private static final String KEEP_ALIVE_PROP = "arpd.keepalive";
	private static final String SEMAPHORE_PROP = "arpd.runfile";
	private static final String ARP_STATUS_PROP = "arpd.status";

	private static final String KEEP_ALIVE_FILE_DEFAULT = "/opt/arpd/arpd.alive";
	private static final String SEMAPHORE_FILE_DEFAULT = "/opt/arpd/arpd.run";
	private static final String ARP_STATUS_FILE_DEFAULT = "/opt/arpd/arpd.status";

	private static final int ARP_STATUS_DUMP_TIME_SECS = 10;
	private static final int ARP_ENTRY_EXPIRE_SECS = 630; // 10m30s
	private static final int ARP_ENTRIES_MAX = 8192;
	private static final int ARP_STATS_LOG_TIME_SECS = 30;
	private static final int PCAP_FRAME_LENGTH = 128;
	private static final int PCAP_TIME_MILLIS = 5;

	private static AtomicLong stats_request = new AtomicLong();
	private static AtomicLong stats_responses = new AtomicLong();
	private static File statusFile = null;
	private static File semaphore = null;
	private static File keepAliveFile = null;
	private static boolean testMode;
	private static Set<String> devices = new HashSet<String>();
	private static Map<String, IpSubnetList> subnets = new HashMap<String, IpSubnetList>();
	private static LinkedHashMap<String, ARPEntry> arpTable = new LinkedHashMap<String, ARPEntry>() {
		private static final long serialVersionUID = 1L;

		// This method is called just after a new entry has been added
		public boolean removeEldestEntry(final Map.Entry<String, ARPEntry> eldest) {
			return (size() > ARP_ENTRIES_MAX);
		}
	};

	private final NetworkInterface my_dev;
	private final JpcapCaptor my_cap;
	private final JpcapSender my_send;
	private final IpSubnetList my_excluded;
	private final IpSubnetList my_included;

	ARPD(final NetworkInterface dev, final JpcapCaptor captor, final JpcapSender sender,
			final IpSubnetList excluded, final IpSubnetList included) {
		this.my_dev = dev;
		this.my_cap = captor;
		this.my_send = sender;
		this.my_excluded = excluded;
		this.my_included = included;
	}

	static void heartBeat() {
		try {
			if (!keepAliveFile.createNewFile()) {
				keepAliveFile.setLastModified(System.currentTimeMillis());
			}
		} catch (Exception ign) {
		}
	}

	static void setSemaphore(final String file) {
		semaphore = new File(file);
	}

	private static volatile boolean lastSemaphoreState = false;

	static boolean checkSemaphore() {
		final boolean newState = semaphore.exists();
		if (newState != lastSemaphoreState) {
			log.warn("CHANGED STATE(" + (lastSemaphoreState ? "RUN" : "DOWN") //
					+ "->" + (newState ? "RUN" : "DOWN") + ")");
			lastSemaphoreState = newState;
		}
		return newState;
	}

	static void setStatus(final String file) {
		statusFile = new File(file);
	}

	static void setKeepAlive(final String file) {
		keepAliveFile = new File(file);
	}

	static void loadConfig(final String file) {
		FileReader fileReader = null;
		BufferedReader cfgReader = null;
		try {
			log.info("Loading config file=" + file);
			fileReader = new FileReader(file);
			cfgReader = new BufferedReader(fileReader);
			testMode = Boolean.parseBoolean(System.getProperty(TEST_MODE_PROP, "true"));
			setStatus(System.getProperty(ARP_STATUS_PROP, ARP_STATUS_FILE_DEFAULT));
			setKeepAlive(System.getProperty(KEEP_ALIVE_PROP, KEEP_ALIVE_FILE_DEFAULT));
			setSemaphore(System.getProperty(SEMAPHORE_PROP, SEMAPHORE_FILE_DEFAULT));
			if (log.isDebugEnabled()) {
				log.debug("conf testMode=" + testMode);
				log.debug("conf semaphoreFile=" + semaphore.getAbsolutePath());
				log.debug("conf keepAliveFile=" + keepAliveFile.getAbsolutePath());
				log.debug("conf statusFile=" + statusFile.getAbsolutePath());
			}

			String line = null;
			final Pattern regExp = Pattern.compile("(-|)\\d+\\.\\d+\\.\\d+\\.\\d+(/.*|)");
			while ((line = cfgReader.readLine()) != null) {
				line = line.trim();
				if (line.startsWith("#"))
					continue;
				final String[] toks = line.split("[ \\t\\s]+", 2);
				if (toks.length < 2) {
					continue;
				}
				final String k = toks[0];
				final String v = toks[1];
				// x.x.x.x = included
				// -x.x.x.x = excluded
				// [-]x.x.x.x = ip
				// [-]x.x.x.x/bb = ip/bits
				// [-]x.x.x.x/y.y.y.y = ip/mask ** TODO
				// [-]x.x.x.x-y.y.y.y = ipRangeBegin-ipRangeEnd ** TODO
				if (regExp.matcher(k).matches()) {
					final String dev = v;
					final IpSubnetList ex, in;
					if (!devices.contains(dev)) { // Inicializa el device
						ex = new IpSubnetList();
						in = new IpSubnetList();
						devices.add(dev);
						subnets.put(dev + EXCLUDE, ex);
						subnets.put(dev + INCLUDE, in);
					} else {
						ex = subnets.get(dev + EXCLUDE);
						in = subnets.get(dev + INCLUDE);
					}
					final boolean excluded = k.startsWith("-");
					final String addr = (excluded ? k.substring(1) : k) + (k.indexOf('/') == -1 ? "/32" : "");
					if (log.isDebugEnabled()) {
						log.debug("conf dev=" + dev + " addr=" + addr + (excluded ? " (EXCLUDED)" : ""));
					}
					(excluded ? ex : in).add(addr);
				}
			}
		} catch (Exception e) {
			log.error("Exception: " + e, e);
			System.exit(-2);
		} finally {
			closeSilent(cfgReader);
			closeSilent(fileReader);
		}
	}

	private static final void closeSilent(final Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Exception ign) {
			}
		}
	}

	public static void main(final String[] args) throws Exception {
		final NetworkInterface[] deviceList = JpcapCaptor.getDeviceList();
		if (args.length < 1) {
			System.out.println("Usage: java ARPD <config>");

			for (int i = 0; i < deviceList.length; i++) {
				final NetworkInterface dev = deviceList[i];
				System.out.println(i + " :" + dev.name + "(" + dev.description + ")");
				System.out.println("    data link:" + dev.datalink_name + "(" + dev.datalink_description
						+ ")");
				System.out.print("    MAC address:");
				for (final byte b : dev.mac_address) {
					System.out.print(Integer.toHexString(b & 0xff) + ":");
				}
				System.out.println();
				for (final NetworkInterfaceAddress a : dev.addresses) {
					System.out.println("    address:" + a.address + " " + a.subnet + " " + a.broadcast);
				}
			}

		} else {
			loadConfig(args[0]); // Cargamos la configuracion
			//
			int started = 0;

			// Inicializamos los spoofers para cada device
			for (int i = 0; i < deviceList.length; i++) {
				final NetworkInterface dev = deviceList[i];
				if (devices.contains(dev.name)) {
					final IpSubnetList excluded = subnets.get(dev.name + EXCLUDE);
					final IpSubnetList included = subnets.get(dev.name + INCLUDE);
					// open Jpcap (interface, snaplen, promisc, time_millis)
					final JpcapCaptor captor = JpcapCaptor.openDevice(dev, PCAP_FRAME_LENGTH, false, PCAP_TIME_MILLIS);
					final JpcapSender sender = JpcapSender.openDevice(dev);
					captor.setFilter(FILTER, true);
					final ARPD arpd = new ARPD(dev, captor, sender, excluded, included);
					final Thread nTh = new Thread(arpd);
					nTh.setDaemon(true);
					nTh.setName("ARP:" + dev.name);
					nTh.start();
					started++;
				}
			}
			log.info("Started " + started + " devices in MODE=" + (testMode ? "TEST" : "REAL") //
					+ " RUN=" + checkSemaphore());

			while (true) {
				try {
					Thread.sleep(1000);
					final long time = System.currentTimeMillis() / 1000L;
					// ARP Status cada 10 segundos
					if ((time % ARP_STATUS_DUMP_TIME_SECS) == 0) {
						final StringBuilder sb = new StringBuilder();
						final ArrayList<String> deletes = new ArrayList<String>();
						final int arpTableSize;
						synchronized (arpTable) {
							arpTableSize = arpTable.size();
							for (final Entry<String, ARPEntry> e : arpTable.entrySet()) {
								final String k = e.getKey();
								final ARPEntry v = e.getValue();
								if ((v.time + ARP_ENTRY_EXPIRE_SECS) < time) {
									deletes.add(k);
								} else {
									sb.append(k).append("\t").append(String.valueOf(v)).append("\n");
								}
							}
							for (final String k : deletes) {
								arpTable.remove(k);
							}
						}
						sb.append("#");
						sb.append(" dump=").append(time);
						sb.append(" entries=").append(arpTableSize);
						sb.append(" request=").append(stats_request.get());
						sb.append(" responses=").append(stats_responses.get());
						sb.append(" mode=").append(testMode ? "TEST" : "REAL");
						sb.append(" run=").append(checkSemaphore());
						sb.append("\n");
						FileOutputStream fos = null;
						PrintStream ps = null;
						try {
							fos = new FileOutputStream(statusFile);
							ps = new PrintStream(fos);
							ps.print(sb.toString());
							ps.flush();
						} finally {
							closeSilent(ps);
							closeSilent(fos);
						}
					}
					// STATS cada 30 segundos
					if (log.isDebugEnabled()) {
						if ((time % ARP_STATS_LOG_TIME_SECS) == 0) {
							log.debug("stats request=" + stats_request.get() + " responses=" + stats_responses.get());
						}
					}
					// HearBeat
					heartBeat();
				} catch (InterruptedException ie) {
				} catch (Exception e) {
					log.error("Exception: " + e, e);
				}
			}
		}
		System.exit(0);
	}

	public void run() {
		log.info("Starting spoofing in device=" + my_dev.name);

		while (true) {
			try {
				final ARPPacket arp = (ARPPacket) my_cap.getPacket();
				if (arp != null) {
					final StringBuilder sb = new StringBuilder();
					final boolean run = checkSemaphore(); // true = run baby! run!
					if (log.isTraceEnabled()) {
						sb.append("rcvd(").append(my_dev.name).append("): ").append(String.valueOf(arp));
					}
					if ((arp.hardtype == ARPPacket.HARDTYPE_ETHER) //
							&& (arp.prototype == ARPPacket.PROTOTYPE_IP) //
							&& (arp.operation == ARPPacket.ARP_REQUEST) //
							&& (arp.hlen == 6) // Ethernet
							&& (arp.plen == 4)) {  // IPv4
						final String targetIP = InetAddress.getByAddress(arp.target_protoaddr)
								.getHostAddress();
						if (log.isTraceEnabled())
							sb.append("CHECKING(").append(targetIP).append(")");
						if (my_excluded.contains(targetIP)) { // REPLY IGNORED
							if (log.isTraceEnabled()) {
								sb.append("(EXCLUDED)");
							}
						} else {
							if (my_included.contains(targetIP)) { // REPLY MATCHED
								if (log.isTraceEnabled()) {
									sb.append("(MATCH)");
								}
								if (run && !testMode) {
									replySend(my_dev, arp, arp.target_protoaddr, my_send);
								} else {
									if (log.isTraceEnabled()) {
										if (testMode) {
											sb.append("(IGNORED-TEST-MODE)");
										}
										if (!run) {
											sb.append("(IGNORED-NO-RUNNING)");
										}
									}
								}
							}
						}
						// Save ARP Status
						final long time = System.currentTimeMillis() / 1000L;
						synchronized (arpTable) {
							arpTable.put(InetAddress.getByAddress(arp.sender_protoaddr).getHostAddress(),
									new ARPEntry(byteToEtherAddress(arp.sender_hardaddr), my_dev.name, time));
						}
					}
					log.trace(sb.toString());
					stats_request.incrementAndGet();
				}
			} catch (Exception e) {
				log.error("Exception: " + e, e);
				try {
					Thread.sleep(1000);
				} catch (Exception ign) {
				}
			}
		}
	}

	// Respondemos con la peticion invertida con la IP indicada
	static void replySend(final NetworkInterface device, final ARPPacket req, final byte[] ip,
			final JpcapSender sender) throws java.io.IOException {
		final ARPPacket arp = new ARPPacket();
		arp.hardtype = ARPPacket.HARDTYPE_ETHER;
		arp.prototype = ARPPacket.PROTOTYPE_IP;
		arp.operation = ARPPacket.ARP_REPLY;
		arp.hlen = 6;
		arp.plen = 4;
		arp.sender_hardaddr = device.mac_address;
		arp.sender_protoaddr = ip;
		arp.target_hardaddr = req.sender_hardaddr;
		arp.target_protoaddr = req.sender_protoaddr;

		final EthernetPacket ether = new EthernetPacket();
		ether.frametype = EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac = device.mac_address;
		ether.dst_mac = req.sender_hardaddr;
		arp.datalink = ether;

		sender.sendPacket(arp);
		stats_responses.incrementAndGet();
	}

	private static String byteToEtherAddress(final byte[] ethAddress) {
		final StringBuilder sb = new StringBuilder(20);
		for (int i = 0; i < ethAddress.length; i++) {
			final int b = (ethAddress[i] & 0xFF);
			if (b < 0x10) {
				sb.append("0");
			}
			sb.append(Integer.toString(b, 16)).append(":");
		}
		sb.setLength(sb.length() - 1); // Delete last ":"
		return sb.toString();
	}

	class ARPEntry {
		public final String mac;
		public final String dev;
		public final long time;

		public ARPEntry(final String mac, final String dev, final long time) {
			this.mac = mac;
			this.dev = dev;
			this.time = time;
		}

		public String toString() {
			return mac + "\t" + dev + "\t" + time;
		}
	}
}
