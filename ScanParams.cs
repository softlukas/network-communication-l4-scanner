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

        // if target ip is domain name, use DNS
        public string Target
        {
            
            get => string.Join(",", _targetIpsList.Select(targetIp => targetIp.IpAddress));
            private set
            {
                if (IPAddress.TryParse(value, out IPAddress ipAddress))
                {

                    SingleIpAddress singleIpAddress = new SingleIpAddress
                    (
                        ipAddress: value,
                        ipFormat: NetworkManager.IsIpv6Address(value) ? IpVersion.IPv6 : IpVersion.IPv4
                    );
                    _targetIpsList.Add(singleIpAddress);
                }
                else
                {
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
            
            //Thread captureThread = new Thread(CaptureResponseTcp);
            //captureThread.Start();

            try {
                ScanTcpPortsIpv6();
            }    
            catch (Exception e)
            {
                Console.WriteLine("Not support ipv6");
            }
           
            
        }
        private void ScanTcpPortsIpv6() {

            // Find the specified network interface
            var devices = CaptureDeviceList.Instance;
            ILiveDevice deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.WriteLine($"Interface {NetworkInterface} not found.");
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

        private void SendSynPacketIpv6(ILiveDevice deviceInterface, ushort destinationPort, string targetIp, bool resending = false) {
            /*
            // Set the destination port
            byte[] destPortBytes = SetPortBytes(destinationPort);

            
            byte[] sourcePortBytes = SetPortBytes(this.sourcePort);

            // Create IPv6 header
            byte[] ipv6Header = new byte[40];
            ipv6Header[0] = 0x60; // Version and traffic class
            // Traffic class and flow label are set to 0
            ushort payloadLength = 20; // Payload length (TCP header only)
            ipv6Header[4] = (byte)(payloadLength >> 8); // High byte
            ipv6Header[5] = (byte)(payloadLength & 0xFF); // Low byte
            ipv6Header[6] = 0x06; // Next header (TCP)
            ipv6Header[7] = 64; // Hop limit

            // Source IP (copy from `SourceIp`)
            Array.Copy(SourceIp, 0, ipv6Header, 8, 16);
            // Destination IP (copy from target IP)
            Array.Copy(IPAddress.Parse(targetIp).GetAddressBytes(), 0, ipv6Header, 24, 16);

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
            ushort tcpChecksum = CalculateChecksum(pseudoHeader);
            tcpHeader[16] = (byte)(tcpChecksum >> 8);
            tcpHeader[17] = (byte)(tcpChecksum & 0xFF);
            try {
                // Create a raw socket
                Socket rawSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Tcp);
                rawSocket.Bind(new IPEndPoint(new IPAddress(SourceIp), 0));

                // rawSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.HeaderIncluded, true);

                // rawSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);

                // Combine IPv6 and TCP headers into one packet
                byte[] packet = new byte[ipv6Header.Length + tcpHeader.Length];
                Array.Copy(ipv6Header, 0, packet, 0, ipv6Header.Length);
                Array.Copy(tcpHeader, 0, packet, ipv6Header.Length, tcpHeader.Length);

                // Send the packet

                rawSocket.SendTo(packet, new IPEndPoint(IPAddress.Parse(targetIp), destinationPort));

                // Close the raw socket
                rawSocket.Close();
            }
            catch (SocketException e)
            {
                Console.WriteLine("Not support ipv6");
                Environment.Exit(1);
            }
            
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

                if (!MatchReplyPortIpAddresses(packetData, destinationPort, this.sourcePort, targetIp))
                {
                    continue;
                }

                // Check if the packet is an IPv6 packet
                if (packetData.Length >= 54 && packetData[6] == 0x06)
                {
                    // Extract the TCP header
                    byte[] tcpHeaderReceived = new byte[20];
                    Array.Copy(packetData, 54, tcpHeaderReceived, 0, 20);

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
            */
        }
        private void ScanTcpPortsIpv4() {

            HashSet<(string ip, ushort port)> pendingSynPackets = new HashSet<(string, ushort)>();

            foreach (string port in TcpPorts)
            {
                foreach (SingleIpAddress targetIp in _targetIpsList)
                {
                    if(targetIp.IpFormat == IpVersion.IPv4)
                    {
                        //Thread thread = new Thread(() => SendSynPacket(ushort.Parse(port), targetIp.IpAddress));
                        //thread.Start();
                        pendingSynPackets.Add((targetIp.IpAddress, ushort.Parse(port)));
                        SendSynPacket(ushort.Parse(port), targetIp.IpAddress);
                        
                    }
            
                }
            }

            CaptureResponseTcp(pendingSynPackets);

        }

        private void CaptureResponseTcp(HashSet<(string ip, ushort port)> pendingSynPackets, bool resending=false) {
            
            // Find the specified network interface
            var devices = CaptureDeviceList.Instance;
            ILiveDevice deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            deviceInterface.Open();

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

                if(!MatchReplyPortIpAddresses(packetData))
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
                        string targetIp = new IPAddress(packetData.Skip(26).Take(4).ToArray()).ToString();

                        // Check if the packet is a SYN-ACK packet
                        if ((tcpHeaderReceived[13] & 0x12) == 0x12) // SYN and ACK flags set
                        {
                            // port is open
                            Console.WriteLine("{0} {1} {2} {3}", targetIp, packetSrcPort, Protocol.tcp, PortState.open);
                            pendingSynPackets.Remove((targetIp, packetSrcPort));
                        }

                        // Check if the packet is a RST packet
                        if ((tcpHeaderReceived[13] & 0x04) == 0x04) // RST flag set
                        {
                            // port is closed
                            Console.WriteLine("{0} {1} {2} {3}", targetIp, packetSrcPort, Protocol.tcp, PortState.closed);
                            pendingSynPackets.Remove((targetIp, packetSrcPort));
                        }

                        
                    }
                }
            }
            
            deviceInterface.Close();
            
            foreach((string ip, ushort port) in pendingSynPackets)
            {
                if(resending == false)
                {
                    //Thread thread = new Thread(() => SendSynPacket(port, ip));
                    //thread.Start();
                    SendSynPacket(port, ip);   
                }
                else
                {
                    Console.WriteLine("{0} {1} {2} {3}", ip, port, Protocol.tcp, PortState.filtered);
                }
            }
            if(resending == false) {
                CaptureResponseTcp(pendingSynPackets, true);
            }
            
            
        }

        
        public void ScanUdpPorts() {

            HashSet<(string ip, ushort port)> pendingUdpPackets = new HashSet<(string, ushort)>();

            foreach (string port in UdpPorts)
            {
                ushort destinationPort = ushort.Parse(port);
                foreach(SingleIpAddress targetIp in _targetIpsList)
                {
                    if(targetIp.IpFormat == IpVersion.IPv4)
                    {
                        pendingUdpPackets.Add((targetIp.IpAddress, destinationPort));
                        SendUdpPacket(destinationPort, targetIp.IpAddress);
                    }
                }   
            }

            CaptureUdpResponse(pendingUdpPackets);
            
        }

        private void CaptureUdpResponse(HashSet<(string ip, ushort port)> pendingUdpPackets) {
            // Find the specified network interface
            var devices = CaptureDeviceList.Instance;
            ILiveDevice deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            deviceInterface.Open();
            
            
            // Set timeout
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

                ushort packetSrcPort = (ushort)((packetData[34] << 8) + packetData[35]);
                string targetIp = new IPAddress(packetData.Skip(26).Take(4).ToArray()).ToString();

                if (!MatchReplyPortIpAddresses(packetData))
                {
                    continue;
                }

                // Check if the packet is an IP packet
                if (packetData.Length >= 34 && packetData[12] == 0x08 && packetData[13] == 0x00)
                {
                    // Check if the packet is a UDP packet
                    if (packetData[23] == 0x11)
                    {
                    

                        // Check if the packet is a port unreachable packet
                        if (packetData[42] == 0x03 && packetData[43] == 0x03) // Type 3, Code 3
                        {
                            // Port is closed
                            pendingUdpPackets.Remove((targetIp, packetSrcPort));
                            Console.WriteLine("{0} {1} {2} {3}", targetIp, packetSrcPort, Protocol.udp, PortState.closed);
                        }
                        
                    }
                }
            }

            foreach((string ip, ushort port) in pendingUdpPackets)
            {
                Console.WriteLine("{0} {1} {2} {3}", ip, port, Protocol.udp, PortState.open);
            }
            deviceInterface.Close();
            
        }

        private void SendUdpPacket(ushort destinationPort, string targetIp, bool resending = false)
        {
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
            
            
        }
                    
        private void SendSynPacket(ushort destinationPort, string targetIp) {
            
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

        }

        private bool MatchReplyPortIpAddresses(byte[] packetData)
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
                    ushort replySrcPort = (ushort)((packetData[34] << 8) + packetData[35]);
                    ushort replyDestPort = (ushort)((packetData[36] << 8) + packetData[37]);
                    // Check if the packet is a TCP packet
                    if (packetData[23] == 0x06) {
                        // Check if the ports match
                        if (TcpPorts.Contains(replySrcPort.ToString()) && replyDestPort == sourcePort)
                        {
                            return true;
                        }
                    }
                    else if (packetData[23] == 0x11) {
                        // Check if the ports match
                        if (UdpPorts.Contains(replySrcPort.ToString()) && replyDestPort == sourcePort)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
            


        private bool MatchIcmpReplyPortIpAddresses(byte[] packetData, ushort destinationPort, ushort sourcePort, string targetIp)
        {
            // Extract outer IP addresses (who sent ICMP)
            byte[] icmpSourceIp = new byte[4];
            byte[] icmpDestIp = new byte[4];
            Array.Copy(packetData, 26, icmpSourceIp, 0, 4);
            Array.Copy(packetData, 30, icmpDestIp, 0, 4);

            // Check if ICMP came from target IP (target IP sent us "port unreachable")
            if (new IPAddress(icmpSourceIp).ToString() == targetIp)
            {
                // Now, get to the "embedded" original IP header (inside ICMP)
                int embeddedIpHeaderStart = 34; // 14 (Ethernet) + 20 (IP)
                int embeddedUdpHeaderStart = embeddedIpHeaderStart + 20; // IP header is 20 bytes

                // Extract source and destination ports from embedded UDP header
                ushort embeddedSrcPort = (ushort)((packetData[embeddedUdpHeaderStart] << 8) + packetData[embeddedUdpHeaderStart + 1]);
                ushort embeddedDestPort = (ushort)((packetData[embeddedUdpHeaderStart + 2] << 8) + packetData[embeddedUdpHeaderStart + 3]);

                // Match ports (original packet's ports)
                if (embeddedSrcPort == sourcePort && embeddedDestPort == destinationPort)
                {
                    return true;
                }
            }

            return false;
        }

        private byte[] SetPortBytes(ushort port) {
            byte[] portBytes = BitConverter.GetBytes(port);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(portBytes);
            }
            return portBytes;
        }

    }
}