

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;

//import de.gtarc.sec.model.DatabaseHandler;

public class FlowCollector extends Thread {

	private PcapIf device;
	StringBuilder errbuf = new StringBuilder();
	public FlowCollector(PcapIf device,StringBuilder errbuf) {
		super();
		this.device = device;
		this.errbuf = errbuf;
	}
	
	public static void main(String[] args) {
		System.out.println("Finding available devices....");
		StringBuilder errbuf = new StringBuilder();
		List<PcapIf> ifs = new ArrayList<PcapIf>(); 
		int statusCode = Pcap.findAllDevs(ifs, errbuf);
		if (statusCode != Pcap.OK) {
			System.out.println("Error occurred: " + errbuf.toString());
			return;
		}
		FlowCollector [] devices = new FlowCollector[10];
		Iterator<PcapIf> iter = ifs.iterator();
		int count = 0;
		while (iter.hasNext()) {
			count++;
			PcapIf next = iter.next();
			System.out.println(next.getDescription() + "\n"
					+ next.getAddresses() + "\n\n");
			PcapIf nextDevice = ifs.get(count -1);
			FlowCollector nfc = new FlowCollector(nextDevice, errbuf);
			devices[count - 1] = nfc;
		}
		System.out.println(count); 
		for(int i = 0; i < count ; i++)
		{
			devices[i].start();
		}
	}
	@Override
	public void run() {
		System.out.println((device.getDescription() != null) ? device
				.getDescription() : device.getName());
	//	DatabaseHandler dH = new DatabaseHandler();
		int snaplen = 64 * 1024; 
		int flags = Pcap.MODE_PROMISCUOUS; 
		int timeout = 10 * 1000; 
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
				errbuf);
		if (pcap == null) {
			System.out.println("Error opening device for capture: "
					+ errbuf.toString());
			return;
		}

		JPacketHandler<String> jpacketBinaryHandler = new JPacketHandler<String>() {
			public void nextPacket(JPacket packet, String user) { 
				int size = packet.size();  
				JBuffer buffer = packet;  

				int ethernetType = buffer.getUShort(12); // 12th byte  

				byte[] array = buffer.getByteArray(0, size);  
  

				ByteBuffer byteBuffer = ByteBuffer.allocate(size);  
				buffer.transferTo(byteBuffer); 
				System.out.println(buffer);

			}
		};

		JPacketHandler<String> jpacketHandler = new JPacketHandler<String>() {
			public void nextPacket(JPacket packet, String user) {
				NetworkPacket pack = new NetworkPacket((PcapPacket) packet);
				Ip4 ip = new Ip4();
				System.out.println(packet);
				if (packet.hasHeader(ip))
				{
					System.out.println("Source IP = "+ FormatUtils.ip(ip.source()) + "Destionation IP = " + FormatUtils.ip(ip.destination()) + "Description =" +  ip.getDescription());
					String jsoncommand = "{\"sourceIP\" : \"" + FormatUtils.ip(ip.source()) + "\", \"destIP\" : \"" + FormatUtils.ip(ip.destination()) + "\", \"description\" : \"" + ip.getDescription() + "\"}";
					//dH.insertElement(FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()), ip.getDescription());
				}
			}
		};
		
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jNetPcap");
		pcap.close();
	}
}
