
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.network.Arp;
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
		System.out.println("-------------------------------------------------------------------------------------------------------\n\n\n");
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		byte[] sIP = new byte[4];
		byte[] dIP = new byte[4];
		String sourceIP = "";
		String destIP = "";

		if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
			sIP = packet.getHeader(ip).source();
			sourceIP = FormatUtils.ip(sIP);
			dIP = packet.getHeader(ip).destination();
			destIP = FormatUtils.ip(dIP);

			System.out.println("*  " + sourceIP + "  *  " + destIP);
			System.out.println();
			System.out.println("Source IP= " + sourceIP);
			System.out.println();
			System.out.println("Destination IP= " + destIP);
			System.out.println();
			System.out.println(tcp.source());
			System.out.println();
			if (tcp.source() == 80) {
				System.out.println("HTTP protocol");
			} else if (tcp.source() == 23) {
				System.out.println("Telnet protocol");
			}else if(tcp.source() == 22){
				System.out.println("SSH protocol");
			}else if(tcp.source() == 25){
				System.out.println("SMTP protocol");
			}else if(tcp.source() == 53){
				System.out.println("DNS protocol");
			}else if(tcp.source() == 110){
				System.out.println("POP3 protocol");
			}else if(tcp.source() == 546){
				System.out.println("DHCP protocol");
			}else if(tcp.source() == 443){
				System.out.println("HTTPS protocol");
			}else if(tcp.source() == 546){
				System.out.println("DHCP protocol");
			}
		}
		
		System.out.println("\n\n\n------------------------------------------------------------------------------------------------------");

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
