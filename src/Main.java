import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Scanner;



public class Main {
	public static void main(String[] args) throws FileNotFoundException {
		
		final String file_name = "input.txt";
		Scanner in = null;
		PrintWriter out = new PrintWriter(new File("output.txt"));
		String bits = "";
		in = new Scanner(new File(file_name));
		bits = in.nextLine();
		in.close();
		if(bits.equals(""))return;
		
		String version_str = bits.substring(0, 4);
		String header_length_str = bits.substring(4,8);
		String total_length_str = bits.substring(16,32);
		String id_str = bits.substring(32,48);
		String reserved = bits.substring(48, 49);
		String dont_fragment = bits.substring(49, 50);
		String more_fragments = bits.substring(50, 51);
		String fragment_offset_str = bits.substring(51,64);
		String ttl_str = bits.substring(64,72);
		String protocol_str = bits.substring(72,80);
		String checksum_str = bits.substring(80,96);
		String source_ip_str = bits.substring(96,128);
		String dest_ip_str = bits.substring(128,160);
		
		String source_port_str = bits.substring(160,176);
		String dest_port_str = bits.substring(176,192);
		String seq_num_str = bits.substring(192,224);
		String ack_num_str = bits.substring(224,256);
		String data_offset_str = bits.substring(256,260);
		String urg_bit = bits.substring(266,267);
		String ack_bit = bits.substring(267,268);
		String psh_bit = bits.substring(268,269);
		String rst_bit = bits.substring(269,270);
		String syn_bit = bits.substring(270,271);
		String fin_bit = bits.substring(271,272);
		String window_size_str = bits.substring(272, 288);
		String data_checksum_str = bits.substring(288,304);
		//304,320
		String data1_str = bits.substring(320, 336);
		String data2_str = bits.substring(336,352);
		String data3_str = bits.substring(352,368);
		String data4_str = bits.substring(368,384);
		
		int version = Integer.valueOf(version_str, 2);
		int header_length = Integer.valueOf(header_length_str, 2);
		int total_length = Integer.valueOf(total_length_str, 2);
		int id = Integer.valueOf(id_str,2);
		int fragment_offset = Integer.valueOf(fragment_offset_str, 2);
		int ttl = Integer.valueOf(ttl_str, 2);
		int protocol = Integer.valueOf(protocol_str, 2);
		int checksum = Integer.valueOf(checksum_str,2);
		
		int source_port = Integer.valueOf(source_port_str,2);
		int dest_port = Integer.valueOf(dest_port_str,2);
		long seq_num = Long.valueOf(seq_num_str,2);
		long ack_num = Long.valueOf(ack_num_str,2);
		int data_offset = Integer.valueOf(data_offset_str, 2);
		int window_size = Integer.valueOf(window_size_str,2);
		long data_checksum = Long.valueOf(data_checksum_str,2);
		int data1=Integer.valueOf(data1_str,2),
				data2=Integer.valueOf(data2_str,2),
				data3=Integer.valueOf(data3_str,2),
				data4=Integer.valueOf(data4_str,2);
		
		out.println("Version: "+version);
		out.println("Header length: "+header_length);
		out.println("Total length: "+total_length);
		out.println("ID: "+id);
		out.println("Flags:");
			out.println("\tReserved: "+reserved);
			out.println("\tDon't Fragment: "+dont_fragment);
			out.println("\tMore Fragments: "+more_fragments);
		out.println("Fragment offset: "+fragment_offset);
		out.println("TTL: "+ttl);
		out.println("Protocol: "+protocol+"("+getProtocol(protocol)+")");
		out.println("Header checksum: "+checksum);
		out.println("Source IP: "+getIPAddress(source_ip_str)+":"+source_port+" Class "+getIPClass(source_ip_str));
		out.println("Destination IP: "+getIPAddress(dest_ip_str)+":"+dest_port+" Class "+getIPClass(dest_ip_str));
		out.println("Sequence number: "+seq_num);
		out.println("Acknowledgement number: "+ack_num);
		out.println("Data Offset: "+data_offset);
		out.println("Flags:");
		out.println("\tUrgent: "+urg_bit);
		out.println("\tAcknowledge: "+ack_bit);
		out.println("\tPSH: "+psh_bit);
		out.println("\tRST: " +rst_bit);
		out.println("\tSync: "+syn_bit);
		out.println("\tFinish: "+fin_bit);
		out.println("Window size: "+window_size);
		out.println("TCP Checksum: "+data_checksum);
		out.println("Data(1) "+data1);
		out.println("Data(2) "+data2);
		out.println("Data(3) "+data3);
		out.println("Data(4) "+data4);
		
		out.close();

	}
	
	private static String getIPClass(String ip){
		String firstOctet = ip.substring(0,8);
		if(firstOctet.charAt(0) == '0') return "A";
		if(firstOctet.charAt(1) == '0') return "B";
		if(firstOctet.charAt(2) == '0') return "C";
		if(firstOctet.charAt(3) == '0') return "D";
		return "E";
	}
	
	private static String getIPAddress(String ip){
		String a = ip.substring(0,8);
		String b = ip.substring(8,16);
		String c = ip.substring(16,24);
		String d = ip.substring(24,32);
		
		return ""+Integer.parseInt(a, 2)+"."+
			Integer.parseInt(b, 2)+"."+
			Integer.parseInt(c, 2)+"."+
			Integer.parseInt(d, 2);
	}
	
	private static String getProtocol(int protocol){
		switch(protocol){
		case 0: return "HOPOPT";
		case 1: return "ICMP";
		case 2: return "IGMP";
		case 3: return "GGP";
		case 4: return "IP-in-IP";
		case 5: return "ST";
		case 6: return "TCP";
		case 7: return "CBT";
		case 8: return "EGP";
		case 9: return "IGP";
		case 10: return "BBN-RCC-MON";
		case 11: return "NVP-II";
		case 12: return "PUP";
		case 13: return "ARGUS";
		case 14: return "EMCON";
		case 15: return "XNET";
		case 16: return "CHAOS";
		case 17: return "UDP";
		case 18: return "MUX";
		case 19: return "DCN-MEAS";
		case 20: return "HMP";
		case 21: return "PRM";
		case 22: return "XNS-IDP";
		case 23: return "TRUNK-1";
		case 24: return "TRUNK-2";
		case 25: return "LEAF-1";
		case 26: return "LEAF-2";
		case 27: return "RDP";
		case 28: return "IRTP";
		case 29: return "ISO-TP4";
		case 30: return "NETBLT";
		case 31: return "MFE-NSP";
		case 32: return "MERIT-INP";
		case 33: return "DCCP";
		case 34: return "3PC";
		case 35: return "IDPR";
		case 36: return "XTP";
		case 37: return "DDP";
		case 38: return "IDPR-CMTP";
		case 39: return "TP";
		case 40: return "IL";
		case 41: return "IPv6";
		case 42: return "SDRP";
		case 43: return "IPv6-Route";
		case 44: return "IPv6-Frag";
		case 45: return "IDRP";
		case 46: return "RSVP";
		case 47: return "GRE";
		case 48: return "MHRP";
		case 49: return "BNA";
		case 50: return "ESP";
		case 51: return "AH";
		case 52: return "I-NLSP";
		case 53: return "SWIPE";
		case 54: return "NARP";
		case 55: return "MOBILE";
		case 56: return "TLSP";
		case 57: return "SKIP";
		case 58: return "IPv6-ICMP";
		case 59: return "IPv6-NoNxt";
		case 60: return "IPv6-Opts";
		case 61: return "";
		case 62: return "CFTP";
		case 63: return "";
		case 64: return "SAT-EXPAK";
		case 65: return "KRYPTOLAN";
		case 66: return "RVD";
		case 67: return "IPPC";
		case 68: return "";
		case 69: return "SAT-MON";
		case 70: return "VISA";
		case 71: return "IPCU";
		case 72: return "CPNX";
		case 73: return "CPHB";
		case 74: return "WSN";
		case 75: return "PVP";
		case 76: return "BR-SAT-MON";
		case 77: return "SUN-ND";
		case 78: return "WB-MON";
		case 79: return "WB-EXPAK";
		case 80: return "ISO-IP";
		case 81: return "VMTP";
		case 82: return "SECURE-VMTP";
		case 83: return "VINES";
		case 84: return "TTP/IPTM";
		case 85: return "NSFNET-IGP";
		case 86: return "DGP";
		case 87: return "TCF";
		case 88: return "EIGRP";
		case 89: return "OSPF";
		case 90: return "Sprite-RPC";
		case 91: return "LARP";
		case 92: return "MTP";
		case 93: return "AX";
		case 94: return "IPIP";
		case 95: return "MICP";
		case 96: return "SCC-SP";
		case 97: return "ETHERIP";
		case 98: return "ENCAP";
		case 99: return "";
		case 100: return "GMTP";
		case 101: return "IFMP";
		case 102: return "PNNI";
		case 103: return "PIM";
		case 104: return "ARIS";
		case 105: return "SCPS";
		case 106: return "QNX";
		case 107: return "A";
		case 108: return "IPComp";
		case 109: return "SNP";
		case 110: return "Compaq-Peer";
		case 111: return "IPX-in-IP";
		case 112: return "VRRP";
		case 113: return "PGM";
		case 114: return "";
		case 115: return "L2TP";
		case 116: return "DDX";
		case 117: return "IATP";
		case 118: return "STP";
		case 119: return "SRP";
		case 120: return "UTI";
		case 121: return "SMP";
		case 122: return "SM";
		case 123: return "PTP";
		case 124: return "IS-IS";
		case 125: return "FIRE";
		case 126: return "CRTP";
		case 127: return "CRUDP";
		case 128: return "SSCOPMCE";
		case 129: return "IPLT";
		case 130: return "SPS";
		case 131: return "PIPE";
		case 132: return "SCTP";
		case 133: return "FC";
		case 134: return "RSVP-E2E-IGNORE";
		case 135: return "Mobility Header";
		case 136: return "UDPLite";
		case 137: return "MPLS-in-IP";
		case 138: return "manet";
		case 139: return "HIP";
		case 140: return "Shim6";
		case 141: return "WESP";
		case 142: return "ROHC";
		case 255: return "Reserved";
		}
		if(protocol>=253 && protocol<=254) return "Used for testing and experimenting";
		if(protocol>=143 && protocol<=252) return "Unassigned";
		return "";
	}

}
