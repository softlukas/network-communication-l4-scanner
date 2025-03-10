using System;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;




namespace proj1
{
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

        private string _targetIp;

        // if target ip is domain name, use DNS
        public string TargetIp
        {
            get => _targetIp;
            private set
            {
                if (IPAddress.TryParse(value, out IPAddress ipAddress))
                {
                    _targetIp = value;
                }
                else
                {
                    _targetIp = ResolveIpAddressFromDomain(value);
                }
                // set ipv4/ipv6
                if(NetworkManager.IsIpv6Address(_targetIp))
                    IpAddressFormat = IpVersion.IPv6;
                else {
                    IpAddressFormat = IpVersion.IPv4;
                }
            }
        }

        public byte[] SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public byte[] TargetMac { get; private set; }
        public int Timeout {get; private set;}

        private string stringSourceIp;
        private string stringTargetIp;
       

        public ScanParams(string? networkInterface, List<string> udpPorts, List<string> tcpPorts, 
        string targetIp, int timeout)
        {
            NetworkInterface = networkInterface;
            UdpPorts = udpPorts;
            TcpPorts = tcpPorts;
            TargetIp = targetIp;
            Timeout = timeout;

            SourceIp = NetworkManager.GetSourceIpAddress(networkInterface, IpAddressFormat);
            stringSourceIp = new IPAddress(SourceIp).ToString();

        }
        
        private string ResolveIpAddressFromDomain(string domain)
        {
            // Pokúsi sa preložiť doménové meno na IP adresu
            try
            {
                var addresses = Dns.GetHostAddresses(domain);
                if (addresses.Length > 0)
                {
                    return addresses[0].ToString(); // Vráti prvú IP adresu z DNS prekladu
                }
                else
                {
                    throw new Exception();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Unable to resolve domain name.");
                Environment.Exit(1);
                return null;
            }
        }    

        public override string ToString()
        {
            return $"Interface: {NetworkInterface ?? "None"}\n" +
                   $"UDP Ports: {string.Join(",", UdpPorts)}\n" +
                   $"TCP Ports: {string.Join(",", TcpPorts)}\n" +
                   $"Target IP: {this._targetIp ?? "None"}\n" +
                   $"Source IP: {stringSourceIp}\n" +
                   $"IpVersion: {IpAddressFormat}\n\n" +
                   $"IpVersion: {IpAddressFormat}\n\n" +
                   $"Timeout: {Timeout}\n\n" +
                    $"Interesting ports on {this._targetIp}:\n";

        }
        
        public void ScanTcpPorts() {
            if(IpAddressFormat == IpVersion.IPv4)
            {
                ScanTcpPortsIpv4();
            }
            else
            {
                ScanTcpPortsIpv6();
            }
        }

        private void ScanTcpPortsIpv4() {

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
                SendSynPacket(deviceInterface, ushort.Parse(port));
            }

            deviceInterface.Close();

        }

        

        public void ScanUdpPorts() {

            Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
    

            // Create a capture device for listening to ICMP responses
            var devices = CaptureDeviceList.Instance;
            ILiveDevice deviceInterface = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (deviceInterface == null)
            {
                Console.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            deviceInterface.Open();
            
            foreach(string destPort in UdpPorts)
            {
                byte[] udpPacket = NetworkManager.BuildUpdPacket(12345, int.Parse(destPort));
                byte[] targetIpBytes = IPAddress.Parse(this._targetIp).GetAddressBytes();

                IPEndPoint target = new IPEndPoint(new IPAddress(targetIpBytes), int.Parse(destPort));
                udpSocket.SendTo(udpPacket, target);
                
                // Set timeout for receiving ICMP response
                DateTime startTime = DateTime.Now;
                TimeSpan timeout = TimeSpan.FromMilliseconds(Timeout);
                bool portMarkedFlag = false;
                while (DateTime.Now - startTime < timeout)
                {
                    PacketCapture rawPacket;
                    // Read the next packet from the network deviceInterface
                    if (deviceInterface.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead)
                    {
                        continue;
                    }

                    byte[] packetData = rawPacket.Data.ToArray();

                    // Check if the packet is an ICMP packet
                    if (packetData.Length >= 28 && packetData[23] == 0x01 && 
                    packetData[34] == 0x03 && packetData[35] == 0x03)
                    {
                       
                        
                        
                        // Extract the source and destination IP addresses
                        byte[] sourceIp = new byte[4];
                        byte[] destIp = new byte[4];
                        Array.Copy(packetData, 26, sourceIp, 0, 4);
                        Array.Copy(packetData, 30, destIp, 0, 4);
                
                        // Check if the packet is from the target IP
                        if (new IPAddress(sourceIp).ToString() == this._targetIp)
                        {
                            Console.WriteLine("{0}/udp closed", destPort);
                            portMarkedFlag = true;
                            break;
                        }
                        
                    }
                    
                        
                    
                }
                if(!portMarkedFlag) {
                    Console.WriteLine("{0}/udp open", destPort);
                }
                
               
                
            }
            deviceInterface.Close();
            
        }

        
        private void SendSynPacket(ILiveDevice deviceInterface, ushort destinationPort, bool resending = false) {
            
            
            // set destination port
            byte[] destPortBytes = BitConverter.GetBytes((ushort)destinationPort);

            // Ensure the byte array is in network byte order (big-endian)
            if (BitConverter.IsLittleEndian)
            {
                // Ensure the byte array is in network byte order (big-endian)
                Array.Reverse(destPortBytes); 
            }

            // Create IP header
            byte[] ipHeader = new byte[20];
            ipHeader[0] = 0x45; // Version and header length
            ipHeader[1] = 0x00; // Type of service

            
            ushort totalLength = (ushort)(20 + 20); 
            ipHeader[2] = (byte)(totalLength >> 8);  // High byte
            ipHeader[3] = (byte)(totalLength & 0xFF); // Low byte

            ipHeader[4] = 0x00; // Identification
            ipHeader[5] = 0x00; // Identification
            ipHeader[6] = 0x40; // Flags and fragment offset
            ipHeader[7] = 0x00; // Fragment offset
            ipHeader[8] = 0x40; // Time to live
            ipHeader[9] = 0x06; // Protocol (TCP)
            ipHeader[10] = 0x00; // Header checksum (to be filled later)
            ipHeader[11] = 0x00; // Header checksum (to be filled later)

            Array.Copy(SourceIp, 0, ipHeader, 12, 4); // Source IP
            // Destination IP
            Array.Copy(IPAddress.Parse(this._targetIp).GetAddressBytes(), 0, ipHeader, 16, 4); 

            // Recalculate IP header checksum
            ushort ipChecksum = CalculateChecksum(ipHeader);
            ipHeader[10] = (byte)(ipChecksum >> 8);
            ipHeader[11] = (byte)(ipChecksum & 0xFF);

            // Create TCP header
            byte[] tcpHeader = new byte[20];
            tcpHeader[0] = 0x30; // Source port (12345)
            tcpHeader[1] = 0x39; // Source port (12345)
            tcpHeader[2] = destPortBytes[0]; // High byte of destination port
            tcpHeader[3] = destPortBytes[1]; // Low byte of destination port


            tcpHeader[4] = 0x00; // Sequence number
            tcpHeader[5] = 0x00; // Sequence number
            tcpHeader[6] = 0x00; // Sequence number
            tcpHeader[7] = 0x00; // Sequence number
            tcpHeader[8] = 0x00; // Acknowledgment number
            tcpHeader[9] = 0x00; // Acknowledgment number
            tcpHeader[10] = 0x00; // Acknowledgment number
            tcpHeader[11] = 0x00; // Acknowledgment number
            tcpHeader[12] = 0x50; // Data offset and reserved
            tcpHeader[13] = 0x02; // Flags (SYN)
            tcpHeader[14] = 0x04; // Window size
            tcpHeader[15] = 0x00; // Window size
            tcpHeader[16] = 0x00; // Checksum (to be filled later)
            tcpHeader[17] = 0x00; // Checksum (to be filled later)
            tcpHeader[18] = 0x00; // Urgent pointer
            tcpHeader[19] = 0x00; // Urgent pointer

            // Create pseudo header for TCP checksum calculation
            byte[] pseudoHeader = new byte[12 + tcpHeader.Length];
            Array.Copy(SourceIp, 0, pseudoHeader, 0, 4); // Source IP
            // Destination IP
            Array.Copy(IPAddress.Parse(this._targetIp).GetAddressBytes(), 0, pseudoHeader, 4, 4); 
            pseudoHeader[8] = 0x00; // Reserved
            pseudoHeader[9] = 0x06; // Protocol (TCP)


            pseudoHeader[10] = (byte)(tcpHeader.Length >> 8);
            pseudoHeader[11] = (byte)(tcpHeader.Length & 0xFF);

            Array.Copy(tcpHeader, 0, pseudoHeader, 12, tcpHeader.Length);


            ushort tcpChecksum = CalculateChecksum(pseudoHeader);
            tcpHeader[16] = (byte)(tcpChecksum >> 8);
            tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

        
            // Create a raw socket
            Socket rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
            rawSocket.Bind(new IPEndPoint(new IPAddress(SourceIp), 0));
            rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            // Enable IP header inclusion
            byte[] optionIn = new byte[4] { 1, 0, 0, 0 };
            byte[] optionOut = new byte[4];

            // Combine IP and TCP headers into a single packet
            byte[] packet = new byte[ipHeader.Length + tcpHeader.Length];
            Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
            Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);

            // Send the packet
            rawSocket.SendTo(packet, new IPEndPoint(IPAddress.Parse(this._targetIp), destinationPort));

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

                // Check if the packet is an IP packet
                if (packetData.Length >= 34 && packetData[12] == 0x08 && packetData[13] == 0x00)
                {
                    // Check if the packet is a TCP packet
                    if (packetData[23] == 0x06)
                    {
                        // Extract the source and destination IP addresses
                        
                        byte[] sourceIp = new byte[4];
                        byte[] destIp = new byte[4];
                        Array.Copy(packetData, 26, sourceIp, 0, 4);
                        Array.Copy(packetData, 30, destIp, 0, 4);

                        // Check if the packet is from the target IP
                        if (new IPAddress(sourceIp).ToString() == this._targetIp)
                        {
                            
                            // Extract the TCP header
                            byte[] tcpHeaderReceived = new byte[20];
                            Array.Copy(packetData, 34, tcpHeaderReceived, 0, 20);

                        
                            // Check if the packet is a SYN-ACK packet
                            if ((tcpHeaderReceived[13] & 0x12) == 0x12) // SYN and ACK flags set
                            {
                                Console.WriteLine("{0}/tcp open", destinationPort);
                                return;
                            }

                            // Check if the packet is a RST packet
                            if ((tcpHeaderReceived[13] & 0x04) == 0x04 && resending == false) // RST flag set
                            {
                                Console.WriteLine("{0}/tcp closed", destinationPort);
                                return;
                            }

                        }
                    }
                }
            }
            // if no response between timeout, send SYN packet again
            if(resending == false)
            {
                SendSynPacket(deviceInterface, destinationPort, true);
            }
            // mark port as filtered after resending
            if(resending == true)
            {
                Console.WriteLine("{0}/tcp filtered", destinationPort);
            }
            


        }
        
        private static ushort CalculateChecksum(byte[] data)
        {
            uint sum = 0;
            for (int i = 0; i < data.Length; i += 2)
            {
                ushort word = (ushort)((data[i] << 8) + (i + 1 < data.Length ? data[i + 1] : 0));
                sum += word;
                if ((sum & 0xFFFF0000) != 0)
                {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
            }
            return (ushort)~sum;
        }
    
    }
}