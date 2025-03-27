using System;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Threading;


namespace proj1
{

    struct SingleIpAddress {

        public string IpAddress { get; private set; }

        public ScanParams.IpVersion IpFormat { get; private set; }
    
        public SingleIpAddress(string ipAddress, ScanParams.IpVersion ipFormat)
        {
            IpAddress = ipAddress;
            IpFormat = ipFormat;
        }
    
    
    }

    class ScanParams
    {
        public string? NetworkInterface { get; private set; }
        public List<string> UdpPorts { get; private set; }
        public List<string> TcpPorts { get; private set; }

        public enum IpVersion
        {
            IPv4,
            IPv6
        }
        
        public IpVersion IpAddressFormat { get; private set; }

        private enum PortState {
            open,
            closed,
            filtered
        }

        private enum Protocol {
            tcp,
            udp
        }

        
        private List<SingleIpAddress> _targetIpsList = new List<SingleIpAddress>();

        
        public string Target
        {
            
            get => string.Join(",", _targetIpsList.Select(targetIp => targetIp.IpAddress));
            private set
            {
                // set ipversion format
                if (IPAddress.TryParse(value, out IPAddress ipAddress))
                {
                    IpAddressFormat = NetworkManager.IsIpv6Address(value) ? IpVersion.IPv6 : IpVersion.IPv4;
                    SingleIpAddress singleIpAddress = new SingleIpAddress
                    (
                        ipAddress: value,
                        ipFormat: IpAddressFormat
                    );
                    _targetIpsList.Add(singleIpAddress);
                }
                else
                {
                    // resolve ip from domain, if target is domain name
                    List<string> stringIpsList = NetworkManager.ResolveIpsFromDomain(value);
                    foreach (string ip in stringIpsList)
                    {
                        SingleIpAddress singleIpAddress = new SingleIpAddress
                        (
                            ipAddress: ip,
                            ipFormat: NetworkManager.IsIpv6Address(ip) ? IpVersion.IPv6 : IpVersion.IPv4
                        );
                        _targetIpsList.Add(singleIpAddress);
                    }
                }
            }
        }

        public byte[] SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public byte[] TargetMac { get; private set; }
        public int Timeout {get; private set;}

        private string stringSourceIp;
        private string stringTargetIp;
        private const ushort sourcePort = 12345;

        private static readonly object _lock = new object();
       
        // set scan params atributes
        public ScanParams(string? networkInterface, List<string> udpPorts, List<string> tcpPorts, 
        string target, int timeout)
        {
            NetworkInterface = networkInterface;
            UdpPorts = udpPorts;
            TcpPorts = tcpPorts;
            Target = target;
            Timeout = timeout;

            SourceIp = NetworkManager.GetSourceIpAddress(networkInterface, IpAddressFormat);
            stringSourceIp = new IPAddress(SourceIp).ToString();

        }
        
        

        public override string ToString()
        {
            return $"Interface: {NetworkInterface ?? "None"}\n" +
                   $"UDP Ports: {string.Join(",", UdpPorts)}\n" +
                   $"TCP Ports: {string.Join(",", TcpPorts)}\n" +
                   $"Target IP: {Target ?? "None"}\n" +
                   $"Source IP: {stringSourceIp}\n" +
                   $"IpVersion: {IpAddressFormat}\n\n" +
                   $"IpVersion: {IpAddressFormat}\n\n" +
                   $"Timeout: {Timeout}\n\n";

        }
        
        public void ScanTcpPorts() {
            
            ScanTcpPortsIpv4();
            ScanTcpPortsIpv6();
        }
        private void ScanTcpPortsIpv6() {

            var devices = CaptureDeviceList.Instance;
            var deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.Error.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            deviceInterface.Open();

            foreach (string port in TcpPorts)
            {

                foreach(SingleIpAddress targetIp in _targetIpsList)
                {
                    if(targetIp.IpFormat == IpVersion.IPv6)
                    {
                        SendSynPacketIpv6(deviceInterface, ushort.Parse(port), targetIp.IpAddress);
                    }
                }
            }

            deviceInterface.Close();

        }

        private void ScanTcpPortsIpv4() {

            var devices = CaptureDeviceList.Instance;
            var deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.Error.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            deviceInterface.Open();

            foreach (string port in TcpPorts)
            {
                foreach (SingleIpAddress targetIp in _targetIpsList)
                {
                    if(targetIp.IpFormat == IpVersion.IPv4)
                    {
                        SendSynPacketIpv4(deviceInterface, ushort.Parse(port), targetIp.IpAddress);
                    }
            
                }
            }

            deviceInterface.Close();
        }

        public void ScanUdpPorts() {
            
            var devices = CaptureDeviceList.Instance;
            var deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.Error.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            deviceInterface.Open();

            foreach (string port in UdpPorts)
            {
                foreach(SingleIpAddress targetIp in _targetIpsList)
                {
                    if(targetIp.IpFormat == IpVersion.IPv4)
                    {
                        SendUdpPacketIpv4(deviceInterface, ushort.Parse(port), targetIp.IpAddress);
                    }
                    if(targetIp.IpFormat == IpVersion.IPv6)
                    {
                        SendUdpPacketIpv6(deviceInterface, ushort.Parse(port), targetIp.IpAddress);
                    }
                }   
            }

            deviceInterface.Close();
            
        }

        private void SendSynPacketIpv6(ICaptureDevice deviceInterface, ushort destinationPort, string targetIp, bool resending = false) 
        {
            // Set the destination port
            byte[] destPortBytes = NetworkManager.SetPortBytes(destinationPort);

            byte[] sourcePortBytes = NetworkManager.SetPortBytes(sourcePort);

            // Create TCP header
            byte[] tcpHeader = new byte[20];
            tcpHeader[0] = sourcePortBytes[0]; // Source port high byte
            tcpHeader[1] = sourcePortBytes[1]; // Source port low byte
            tcpHeader[2] = destPortBytes[0];   // Destination port high byte
            tcpHeader[3] = destPortBytes[1];   // Destination port low byte

            // Sequence number (4B, set to 0)
            tcpHeader[4] = 0x00;
            tcpHeader[5] = 0x00;
            tcpHeader[6] = 0x00;
            tcpHeader[7] = 0x00;

            // Acknowledgment number (4B, set to 0)
            tcpHeader[8] = 0x00;
            tcpHeader[9] = 0x00;
            tcpHeader[10] = 0x00;
            tcpHeader[11] = 0x00;

            // Data offset (5 << 4), Flags (SYN)
            tcpHeader[12] = 0x50; // Data offset = 5 (20 bytes), Reserved = 0
            tcpHeader[13] = 0x02; // SYN flag

            // Window size
            tcpHeader[14] = 0x04; // Window size
            tcpHeader[15] = 0x00;

            // Checksum (to be calculated later)
            tcpHeader[16] = 0x00;
            tcpHeader[17] = 0x00;

            // Urgent pointer (set to 0)
            tcpHeader[18] = 0x00;
            tcpHeader[19] = 0x00;

            // Create pseudo header for TCP checksum calculation
            byte[] pseudoHeader = new byte[40 + tcpHeader.Length];
            Array.Copy(SourceIp, 0, pseudoHeader, 0, 16); // Source IP
            Array.Copy(IPAddress.Parse(targetIp).GetAddressBytes(), 0, pseudoHeader, 16, 16); // Destination IP
            pseudoHeader[32] = 0x00; // Reserved
            pseudoHeader[33] = 0x06; // Protocol (TCP)
            pseudoHeader[34] = (byte)(tcpHeader.Length >> 8);
            pseudoHeader[35] = (byte)(tcpHeader.Length & 0xFF);
            Array.Copy(tcpHeader, 0, pseudoHeader, 36, tcpHeader.Length);

            // Calculate the checksum for the TCP header
            ushort tcpChecksum = NetworkManager.CalculateChecksum(pseudoHeader);
            tcpHeader[16] = (byte)(tcpChecksum >> 8);
            tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

            // Create a raw socket
            Socket rawSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Tcp);
            rawSocket.Bind(new IPEndPoint(new IPAddress(SourceIp), 0));
            rawSocket.SendTo(tcpHeader, new IPEndPoint(IPAddress.Parse(targetIp), 0));

            // Close the raw socket
            rawSocket.Close();
            
            // set timeout
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromMilliseconds(Timeout);

            while (DateTime.Now - startTime < timeout)
            {
                PacketCapture rawPacket;

                // Read the next packet from the network deviceInterface
                if (deviceInterface.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead)
                {
                    continue;
                }

                byte[] packetData = rawPacket.Data.ToArray();
                

                if(!Ipv6MatchReplyPortAddress(packetData, destinationPort))
                {
                    continue;
                }

                // Check if the packet is an IPv6 packet
                if (packetData.Length >= 54 && packetData[6] == 0x06)
                {
                    // Check if the packet is an IPv6 packet with a TCP header
                    int nextHeader = packetData[6]; // IPv6 Next Header field
                    int offset = 40; // IPv6 base header size

                    // Skip any extension headers to find the TCP header
                    while (nextHeader != 0x06) // 0x06 = TCP protocol
                    {
                        if (offset + 1 >= packetData.Length)
                            break;
                        
                        nextHeader = packetData[offset]; // Next Header field
                        offset += packetData[offset + 1] + 8; // Length of extension header
                        
                        if (offset >= packetData.Length)
                            break;
                    }

                    // Ensure there is enough data for a TCP header
                    if (packetData.Length < offset + 20)
                        continue;
                    
                    // Extract the TCP header
                    byte[] tcpHeaderReceived = new byte[20];
                    Array.Copy(packetData, offset, tcpHeaderReceived, 0, 20);

                    // Check if the packet is a SYN-ACK packet
                    if ((tcpHeaderReceived[13] & 0x12) == 0x12) // SYN and ACK flags set
                    {
                        // port is open
                        Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.tcp, PortState.open);
                        return;
                    }

                    // Check if the packet is a RST packet
                    if ((tcpHeaderReceived[13] & 0x04) == 0x04 && resending == false) // RST flag set
                    {
                        // port is closed
                        Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.tcp, PortState.closed);
                        return;
                    }
                }
            }
                
            // if no response between timeout, send SYN packet again
            if (resending == false)
            {
                SendSynPacketIpv6(deviceInterface, destinationPort, targetIp, true);
            }
            // mark port as filtered after resending
            if (resending == true)
            {
                // port is filtered
                Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.tcp, PortState.filtered);
            }
        }

        private void SendUdpPacketIpv6(ICaptureDevice deviceInterface, ushort destinationPort, string targetIp, bool resending = false) {
            // Set the destination port
            byte[] destPortBytes = NetworkManager.SetPortBytes(destinationPort);
            byte[] sourcePortBytes = NetworkManager.SetPortBytes(sourcePort);

            const ushort destUnreacheable = 1;
            const ushort portUnreachableCode = 4;

            // Create UDP header
            byte[] udpHeader = new byte[8];
            udpHeader[0] = sourcePortBytes[0]; // Source port high byte
            udpHeader[1] = sourcePortBytes[1]; // Source port low byte
            udpHeader[2] = destPortBytes[0];   // Destination port high byte
            udpHeader[3] = destPortBytes[1];   // Destination port low byte
            udpHeader[4] = 0x00; // Length high byte (placeholder)
            udpHeader[5] = 0x08; // Length low byte (8 bytes UDP header)

            // Calculate UDP checksum
            byte[] pseudoHeader = new byte[40 + udpHeader.Length];
            Array.Copy(SourceIp, 0, pseudoHeader, 0, 16); // Source IP
            Array.Copy(IPAddress.Parse(targetIp).GetAddressBytes(), 0, pseudoHeader, 16, 16); // Destination IP
            pseudoHeader[32] = 0x00; // Reserved
            pseudoHeader[33] = 0x11; // Protocol (UDP)
            pseudoHeader[34] = 0x00; // UDP length high byte
            pseudoHeader[35] = 0x08; // UDP length low byte
            Array.Copy(udpHeader, 0, pseudoHeader, 36, udpHeader.Length);

            ushort udpChecksum = NetworkManager.CalculateChecksum(pseudoHeader);
            udpHeader[6] = (byte)(udpChecksum >> 8);
            udpHeader[7] = (byte)(udpChecksum & 0xFF);
            

            // Create raw socket
            Socket rawSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Udp);
            rawSocket.Bind(new IPEndPoint(new IPAddress(SourceIp), 0));
            rawSocket.SendTo(udpHeader, new IPEndPoint(IPAddress.Parse(targetIp), 0));
            rawSocket.Close();

            // Set timeout
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromMilliseconds(Timeout);

            while (DateTime.Now - startTime < timeout) {

                PacketCapture rawPacket;

                // Read the next packet from the network device
                if (deviceInterface.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead) {
                    continue;
                }

                byte[] packetData = rawPacket.Data.ToArray();

                if (!Ipv6MatchReplyPortAddressUdp(packetData, destinationPort)) {
                    continue;
                }

                
                // Check if the packet is an ICMPv6 message (Type 3, Code 3 = Port Unreachable)
                if (packetData.Length >= 48 && packetData[40] == destUnreacheable && packetData[41] == portUnreachableCode) {
                    // Port is closed
                    Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.udp, PortState.closed);
                    return;
                }
            }

            // If no ICMP error response was received, assume the port is open
            Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.udp, PortState.open);
        }
                
        private void SendUdpPacketIpv4(ICaptureDevice deviceInterface, ushort destinationPort, string targetIp, bool resending = false)
        {
            const ushort destUnreacheable = 3;
            const ushort portUnreachableCode = 3;

            Packet packet = new Packet(destinationPort, 12345, SourceIp, targetIp, Packet.Protocol.Udp);
            
            byte[] udpPacket = packet.BuildPacket();

            // Create a raw socket
            Socket rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
            rawSocket.Bind(new IPEndPoint(new IPAddress(SourceIp), 0));
            rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);


            // Send the packet
            rawSocket.SendTo(udpPacket, new IPEndPoint(IPAddress.Parse(targetIp), destinationPort));

            // Close the UDP socket
            rawSocket.Close();

            // Set timeout
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromMilliseconds(Timeout);

            while (DateTime.Now - startTime < timeout) {

                PacketCapture rawPacket;

                // Read the next packet from the network device
                if (deviceInterface.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead) {
                    continue;
                }

                byte[] packetData = rawPacket.Data.ToArray();

                if(!MatchReplyPortIpAddress(packetData, destinationPort, Protocol.udp)) {
                    continue;
                }
                
                // Check if the packet is an ICMPv6 message (Type 3, Code 3 = Port Unreachable)
                if (packetData.Length >= 48 && packetData[34] == destUnreacheable && packetData[35] == portUnreachableCode) {
                    // Port is closed
                    Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.udp, PortState.closed);
                    return;
                }
            }

            // If no ICMP error response was received, assume the port is open
            Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.udp, PortState.open);


            
            
        }
                    
        private void SendSynPacketIpv4(ICaptureDevice deviceInterface, ushort destinationPort, string targetIp, bool resending=false) {
            
            Packet packet = new Packet(destinationPort, 12345, SourceIp, targetIp, Packet.Protocol.Tcp);
            byte[] tcpSynPacket = packet.BuildPacket();

            // Create a raw socket
            Socket rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
            rawSocket.Bind(new IPEndPoint(new IPAddress(SourceIp), 0));
            rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            // Send the packet
            rawSocket.SendTo(tcpSynPacket, new IPEndPoint(IPAddress.Parse(targetIp), destinationPort));
           
            // Close the raw socket
            rawSocket.Close();

            // set timeout
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromMilliseconds(Timeout);

            while (DateTime.Now - startTime < timeout)
            {

                PacketCapture rawPacket;
                // Read the next packet from the network deviceInterface
                if (deviceInterface.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead)
                {
                    continue;
                }

                byte[] packetData = rawPacket.Data.ToArray();

                if(!MatchReplyPortIpAddress(packetData, destinationPort, Protocol.tcp))
                {
                    continue;
                }
                
                // Check if the packet is an IP packet
                if (packetData.Length >= 34 && packetData[12] == 0x08 && packetData[13] == 0x00)
                {
                    
                    // Check if the packet is a TCP packet
                    if (packetData[23] == 0x06)
                    {
                        
                        // Extract the TCP header
                        byte[] tcpHeaderReceived = new byte[20];
                        Array.Copy(packetData, 34, tcpHeaderReceived, 0, 20);
                    
                        ushort packetSrcPort = (ushort)((packetData[34] << 8) + packetData[35]);
                        //string targetIp = new IPAddress(packetData.Skip(26).Take(4).ToArray()).ToString();

                        // Check if the packet is a SYN-ACK packet
                        if ((tcpHeaderReceived[13] & 0x12) == 0x12) // SYN and ACK flags set
                        {
                            // port is open
                            Console.WriteLine("{0} {1} {2} {3}", targetIp, packetSrcPort, Protocol.tcp, PortState.open);
                            return;
                        }

                        // Check if the packet is a RST packet
                        if ((tcpHeaderReceived[13] & 0x04) == 0x04) // RST flag set
                        {
                            // port is closed
                            Console.WriteLine("{0} {1} {2} {3}", targetIp, packetSrcPort, Protocol.tcp, PortState.closed);
                            return;
                            
                        }

                        
                    }
                }
            }
            
            // if no response between timeout, send SYN packet again
            if (resending == false)
            {
                SendSynPacketIpv4(deviceInterface, destinationPort, targetIp, true);
            }
            // mark port as filtered after resending
            if (resending == true)  
            {
                // port is filtered
                Console.WriteLine("{0} {1} {2} {3}", targetIp, destinationPort, Protocol.tcp, PortState.filtered);
            }
        }

        private bool MatchReplyPortIpAddress(byte[] packetData, ushort testedPort, Protocol protocol)
        {
            
            // Extract the source and destination IP addresses
            byte[] sourceIp = new byte[4];
            byte[] destIp = new byte[4];
            Array.Copy(packetData, 26, sourceIp, 0, 4);
            Array.Copy(packetData, 30, destIp, 0, 4);

            // Check if the packet is from the target IP
            if (_targetIpsList.Any(ip => ip.IpAddress == new IPAddress(sourceIp).ToString())) 
            {
                
                if (new IPAddress(destIp).ToString() == new IPAddress(SourceIp).ToString()) {
                    
                    // Extract the source and destination ports
                    ushort replySrcPort = 0;    
                    ushort replyDestPort = 0;   

                    if(protocol == Protocol.tcp) {
                        replySrcPort = (ushort)((packetData[34] << 8) + packetData[35]);
                        replyDestPort = (ushort)((packetData[36] << 8) + packetData[37]);
                    }

                    if(protocol == Protocol.udp) {
                        replySrcPort = (ushort)((packetData[64] << 8) + packetData[65]);
                        replyDestPort = (ushort)((packetData[62] << 8) + packetData[63]);
                    }
                    
                    // Check if the packet is a TCP packet
                    if (packetData[23] == 0x06) {
                        // Check if the ports match
                        if (replySrcPort == testedPort && replyDestPort == sourcePort)
                        {
                            return true;
                        }
                    }
                    
                    // Check if the ports match
                    if (replySrcPort == testedPort && replyDestPort == sourcePort)
                    {
                        
                        return true;
                    }
                    
                }
            }
            return false;
        }

        private bool Ipv6MatchReplyPortAddress(byte[] packetData, ushort testedPort) 
        {
            
            // Extract the source and destination IP addresses for IPv6
            byte[] sourceIp = new byte[16];
            byte[] destIp = new byte[16];

            // For IPv6, the source IP starts at byte 8 and destination at byte 24
            Array.Copy(packetData, 8, sourceIp, 0, 16);
            Array.Copy(packetData, 24, destIp, 0, 16);

            // Check if the packet is from the target IP (IPv6)
            if (_targetIpsList.Any(ip => ip.IpAddress == new IPAddress(sourceIp).ToString())) 
            {
                if (new IPAddress(destIp).ToString() == new IPAddress(SourceIp).ToString()) {
                    // Extract the source and destination ports for IPv6
                    ushort replySrcPort = (ushort)((packetData[40] << 8) + packetData[41]); // Adjusted for IPv6
                    ushort replyDestPort = (ushort)((packetData[42] << 8) + packetData[43]); // Adjusted for IPv6

                    // Check if the packet is a TCP packet (IPv6 header is 40 bytes long)
                    if (packetData[6] == 0x06) {  // Protocol type for TCP in IPv6
                        // Check if the ports match
                        if (replySrcPort == testedPort && replyDestPort == sourcePort)
                        {
                            return true;
                        }
                    }
                    // Check if the packet is a UDP packet (IPv6 header is 40 bytes long)
                    else if (packetData[6] == 0x11) {  // Protocol type for UDP in IPv6
                        // Check if the ports match
                        if (replySrcPort == testedPort && replyDestPort == sourcePort)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

            
        private bool Ipv6MatchReplyPortAddressUdp(byte[] packetData, ushort testedPort) 
        {
            // Extract the source and destination IP addresses for IPv6
            byte[] sourceIp = new byte[16];
            byte[] destIp = new byte[16];

            // For IPv6, the source IP starts at byte 8 and destination at byte 24
            Array.Copy(packetData, 8, sourceIp, 0, 16);
            Array.Copy(packetData, 24, destIp, 0, 16);
            // Check if the packet is from the target IP (IPv6)
            if (_targetIpsList.Any(ip => ip.IpAddress == new IPAddress(sourceIp).ToString())) 
            {
                
                if (new IPAddress(destIp).ToString() == new IPAddress(SourceIp).ToString()) {
                    
                    ushort replySrcPort = (ushort)((packetData[90] << 8) + packetData[91]); // Correct offset for IPv6
                    ushort replyDestPort = (ushort)((packetData[88] << 8) + packetData[89]); // Correct offset for IPv6
                    
                    if (replySrcPort == testedPort && replyDestPort == sourcePort)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        

    }
}