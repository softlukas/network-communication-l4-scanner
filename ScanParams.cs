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
        public string TargetIp { get; private set; }
        public byte[] SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public byte[] TargetMac { get; private set; }

        private string stringSourceIp;
        private string stringTargetIp;
        private string stringSourceMac;
        private string stringTargetMac;

        public ScanParams(string? networkInterface, List<string> udpPorts, List<string> tcpPorts, 
        string targetIp, byte[] sourceIp, byte[] sourceMac, byte[] targetMac)
        {
            NetworkInterface = networkInterface;
            UdpPorts = udpPorts;
            TcpPorts = tcpPorts;
            TargetIp = targetIp;
            SourceIp = sourceIp;
            SourceMac = sourceMac;
            TargetMac = targetMac;

            stringSourceMac = BitConverter.ToString(SourceMac);
            stringTargetMac = BitConverter.ToString(TargetMac);
            stringSourceIp = new IPAddress(SourceIp).ToString();

        }


        public override string ToString()
        {
            return $"Interface: {NetworkInterface ?? "None"}\n" +
                   $"UDP Ports: {string.Join(",", UdpPorts)}\n" +
                   $"TCP Ports: {string.Join(",", TcpPorts)}\n" +
                   $"Target IP: {TargetIp ?? "None"}\n" +
                   $"Source IP: {stringSourceIp}\n" +
                   $"Source MAC: {stringSourceMac}\n" +
                   $"Target MAC: {stringTargetMac}";
        }
        
        public void ScanTcpPorts() {

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
                Console.WriteLine($"Scanning TCP port {port}...");
                SendSynPacket(deviceInterface);
            }

            deviceInterface.Close();

        }

        public void UdpScan() {
            foreach (string port in UdpPorts)
            {
                Console.WriteLine($"Scanning UDP port {port}...");
                UdpClient udpClient = new UdpClient();
                udpClient.Client.ReceiveTimeout = 5000;
                try
                {
                    udpClient.Connect(TargetIp, int.Parse(port));
                    udpClient.Send(new byte[] { 0 }, 1);
                    IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    byte[] response = udpClient.Receive(ref remoteEndPoint);
                    Console.WriteLine($"UDP port {port} open.");
                }
                catch (SocketException)
                {
                    Console.WriteLine($"UDP port {port} closed.");
                }
                finally
                {
                    udpClient.Close();
                }
            }
        }

        
        private void SendSynPacket(ILiveDevice deviceInterface) {
            
            // Create Ethernet frame
            byte[] ethernetFrame = new byte[14];
            Array.Copy(TargetMac, 0, ethernetFrame, 0, 6); // Destination MAC
            Array.Copy(SourceMac, 0, ethernetFrame, 6, 6); // Source MAC
            ethernetFrame[12] = 0x08; // Ethernet type (IPv4)
            ethernetFrame[13] = 0x00;

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
            Array.Copy(IPAddress.Parse(TargetIp).GetAddressBytes(), 0, ipHeader, 16, 4); // Destination IP

            // Recalculate IP header checksum
            ushort ipChecksum = CalculateChecksum(ipHeader);
            ipHeader[10] = (byte)(ipChecksum >> 8);
            ipHeader[11] = (byte)(ipChecksum & 0xFF);

            // Create TCP header
            byte[] tcpHeader = new byte[20];
            tcpHeader[0] = 0x30; // Source port (12345)
            tcpHeader[1] = 0x39; // Source port (12345)
            tcpHeader[2] = 0x00; // High byte of destination port (80)
            tcpHeader[3] = 0x50; // Low byte of destination port (80)
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
            Array.Copy(IPAddress.Parse(TargetIp).GetAddressBytes(), 0, pseudoHeader, 4, 4); // Destination IP
            pseudoHeader[8] = 0x00; // Reserved
            pseudoHeader[9] = 0x06; // Protocol (TCP)


            pseudoHeader[10] = (byte)(tcpHeader.Length >> 8);
            pseudoHeader[11] = (byte)(tcpHeader.Length & 0xFF);

            Array.Copy(tcpHeader, 0, pseudoHeader, 12, tcpHeader.Length);


            ushort tcpChecksum = CalculateChecksum(pseudoHeader);
            tcpHeader[16] = (byte)(tcpChecksum >> 8);
            tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

            // Combine Ethernet, IP, and TCP headers into a single packet
            byte[] packet = new byte[ethernetFrame.Length + ipHeader.Length + tcpHeader.Length];
            Console.WriteLine("Packet length: " + packet.Length);
            Array.Copy(ethernetFrame, 0, packet, 0, ethernetFrame.Length);
            Array.Copy(ipHeader, 0, packet, ethernetFrame.Length, ipHeader.Length);
            Array.Copy(tcpHeader, 0, packet, ethernetFrame.Length + ipHeader.Length, tcpHeader.Length);

            // Send the packet
            deviceInterface.SendPacket(packet);

            Console.WriteLine("SYN packet sent!");
        
            // set timeout
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromSeconds(5);

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
                        if (new IPAddress(sourceIp).ToString() == TargetIp)
                        {
                            
                            // Extract the TCP header
                            byte[] tcpHeaderReceived = new byte[20];
                            Array.Copy(packetData, 34, tcpHeaderReceived, 0, 20);

                        
                            // Check if the packet is a SYN-ACK packet
                            if ((tcpHeaderReceived[13] & 0x12) == 0x12) // SYN and ACK flags set
                            {
                                Console.WriteLine($"SYN-ACK received from {new IPAddress(sourceIp)}");
                                Console.WriteLine("Port is open.");
                                break;
                            }

                            // Check if the packet is a RST packet
                            if ((tcpHeaderReceived[13] & 0x04) == 0x04) // RST flag set
                            {
                                Console.WriteLine($"RST received from {new IPAddress(sourceIp)}");
                                Console.WriteLine("Port is closed.");
                            }

                        }
                    }
                }
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