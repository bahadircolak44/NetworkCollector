
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.PcapSockAddr;


public class NetworkPacket {

	private static String SourceIp;
	private static String SourcePort;
	private static String TargetIp;
	private static String TargetPort;

	public NetworkPacket(PcapPacket packet) {
		System.out.println(
				"\n-------------------------------------------------------------------------------------------------------\n\n\n");
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		Udp udp = new Udp();
		byte[] sIP = new byte[4];
		byte[] dIP = new byte[4];
		String sourceIP = "";
		String destIP = "";
		if (packet.hasHeader(ip)) {
			sIP = packet.getHeader(ip).source();
			sourceIP = FormatUtils.ip(sIP);
			dIP = packet.getHeader(ip).destination();
			destIP = FormatUtils.ip(dIP);
			System.out.println("*  " + sourceIP + "  *  " + destIP);
			System.out.println();
			System.out.println("Source IP= " + sourceIP);
			System.out.println("Destination IP= " + destIP);
			System.out.println();
			if (packet.hasHeader(tcp)) {
				FindSourcePortName(tcp.source(), "TCP");
				
				FindDestinationPortName(tcp.destination(), "TCP");
			} else
				System.out.println("No TCP Protocol......");
			if (packet.hasHeader(udp)) {
				FindSourcePortName(udp.source(), "UDP");
				FindDestinationPortName(udp.destination(), "UDP");
			} else
				System.out.println("No UDP Protocol......");
		} else
			System.out.println("No IP......");

		System.out.println(
				"\n\n\n------------------------------------------------------------------------------------------------------");

	}

	private static void FindSourcePortName(int port, String name) {
		System.out.println("Source " + name + " number= " + port);

		if (port == 80) {
			System.out.println("Source " + name + " protocol name=  HTTP ");
		} else if (port == 23) {
			System.out.println("Source " + name + " protocol name= Telnet");
		} else if (port == 22) {
			System.out.println("Source " + name + " protocol name= SSH ");
		} else if (port == 25) {
			System.out.println("Source " + name + " protocol name= SMTP ");
		} else if (port == 53) {
			System.out.println("Source " + name + " protocol name= DNS ");
		} else if (port == 110) {
			System.out.println("Source " + name + " protocol name= POP3 ");
		} else if (port == 546) {
			System.out.println("Source " + name + " protocol name= DHCP ");
		} else if (port == 443) {
			System.out.println("Source " + name + " protocol name= HTTPS ");
		} else if (port == 546) {
			System.out.println("Source " + name + " protocol name= DHCP ");
		} else if (port >= 48620 && port <= 49150) {
			System.out.println("Source " + name + " protocol name= Unassigned");
		} else {
			System.out.println("Source " + name + " protocol= Unknown");
		}
	}

	private static void FindDestinationPortName(int port, String name) {
		System.out.println("Destination " + name + " number= " + port);
		if (port == 80) {
			System.out.println("Destination " + name + " protocol name=  HTTP ");
		} else if (port == 23) {
			System.out.println("Destination " + name + " protocol name= Telnet");
		} else if (port == 22) {
			System.out.println("Destination " + name + " protocol name= SSH ");
		} else if (port == 25) {
			System.out.println("Destination " + name + " protocol name= SMTP ");
		} else if (port == 53) {
			System.out.println("Destination " + name + " protocol name= DNS ");
		} else if (port == 110) {
			System.out.println("Destination " + name + " protocol name= POP3 ");
		} else if (port == 546) {
			System.out.println("Destination " + name + " protocol name= DHCP ");
		} else if (port == 443) {
			System.out.println("Destination " + name + " protocol name= HTTPS ");
		} else if (port == 546) {
			System.out.println("Destination " + name + " protocol name= DHCP ");
		} else if (port >= 48620 && port <= 49150) {
			System.out.println("Destination " + name + " protocol name= Unassigned");
		} else {
			System.out.println("Destination " + name + " protocol name= Unknown");
		}
	}

	public static String getSourceIp() {
		return SourceIp;
	}

	public static void setSourceIp(String sourceIp) {
		SourceIp = sourceIp;
	}

	public static String getSourcePort() {
		return SourcePort;
	}

	public static void setSourcePort(String sourcePort) {
		SourcePort = sourcePort;
	}

	public static String getTargetIp() {
		return TargetIp;
	}

	public static void setTargetIp(String targetIp) {
		TargetIp = targetIp;
	}

	public static String getTargetPort() {
		return TargetPort;
	}

	public static void setTargetPort(String targetPort) {
		TargetPort = targetPort;
	}

}
