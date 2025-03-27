using System;
using System.Net;

namespace proj1 {

    class Packet {

        public ushort DestPort { get; private set; }
        public ushort SrcPort { get; private set; }
        public byte[] SourceIp { get; private set; }
        public string TargetIp { get; private set; }
        
        public enum Protocol {
            Tcp = 0x06,
            Udp = 17
        }

        private Protocol protocol;

        // packet constructor
        public Packet(ushort destPort, ushort srcPort, byte[] sourceIp, string targetIp, Protocol protocol) {
            DestPort = destPort;
            SrcPort = srcPort;
            SourceIp = sourceIp;
            TargetIp = targetIp;
            this.protocol = protocol;
        }

        public byte[] BuildPacket() {

            // set destination port
            byte[] destPortBytes = NetworkManager.SetPortBytes(DestPort);

            byte[] SrcPortBytes = NetworkManager.SetPortBytes(SrcPort);
            
            // Create IP header
            byte[] ipHeader = new byte[20];
            ipHeader[0] = 0x45; // Version and header length
            ipHeader[1] = 0x00; // Type of service

            ushort totalLength = protocol == Protocol.Tcp ? (ushort)(20 + 20) : (ushort)(20 + 8);
            
            ipHeader[2] = (byte)(totalLength >> 8);  // High byte
            ipHeader[3] = (byte)(totalLength & 0xFF); // Low byte

            ipHeader[4] = 0x00; // Identification
            ipHeader[5] = 0x00; // Identification
            ipHeader[6] = 0x40; // Flags and fragment offset
            ipHeader[7] = 0x00; // Fragment offset
            ipHeader[8] = 0x40; // Time to live

            ipHeader[9] = (byte)protocol; // Protocol (TCP)
            ipHeader[10] = 0x00; // Header checksum (to be filled later)
            ipHeader[11] = 0x00; // Header checksum (to be filled later)

            Array.Copy(SourceIp, 0, ipHeader, 12, 4); // Source IP
            // Destination IP
            Array.Copy(IPAddress.Parse(TargetIp).GetAddressBytes(), 0, ipHeader, 16, 4); 

            // Recalculate IP header checksum
            ushort ipChecksum = NetworkManager.CalculateChecksum(ipHeader);
            ipHeader[10] = (byte)(ipChecksum >> 8);
            ipHeader[11] = (byte)(ipChecksum & 0xFF);
            
            
            byte [] tcpUdpHeader = null;

            if(protocol == Protocol.Tcp) {
                tcpUdpHeader = CreatetcpUdpHeader(destPortBytes, SrcPortBytes);
            
                // Create pseudo header for TCP checksum calculation
                byte[] pseudoHeader = new byte[12 + tcpUdpHeader.Length];
                Array.Copy(SourceIp, 0, pseudoHeader, 0, 4); // Source IP
                // Destination IP
                Array.Copy(IPAddress.Parse(TargetIp).GetAddressBytes(), 0, pseudoHeader, 4, 4); 
                pseudoHeader[8] = 0x00; // Reserved
                pseudoHeader[9] = (byte)protocol; // Protocol (TCP)
                pseudoHeader[10] = (byte)(tcpUdpHeader.Length >> 8);
                pseudoHeader[11] = (byte)(tcpUdpHeader.Length & 0xFF);

                Array.Copy(tcpUdpHeader, 0, pseudoHeader, 12, tcpUdpHeader.Length);

                ushort tcpChecksum = NetworkManager.CalculateChecksum(pseudoHeader);
                tcpUdpHeader[16] = (byte)(tcpChecksum >> 8);
                tcpUdpHeader[17] = (byte)(tcpChecksum & 0xFF);

            }
            else {
                tcpUdpHeader = CreateUdpHeader(destPortBytes, SrcPortBytes);
            }

            // Combine IP and TCP headers into a single packet
            byte[] packet = new byte[ipHeader.Length + tcpUdpHeader.Length];
            Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
            Array.Copy(tcpUdpHeader, 0, packet, ipHeader.Length, tcpUdpHeader.Length);

            return packet;
        }

        private byte[] CreateUdpHeader(byte[] destPortBytes, byte[] srcPortBytes) {
            // Create UDP header
            byte[] udpHeader = new byte[8];
            udpHeader[0] = srcPortBytes[0]; // Source port high byte
            udpHeader[1] = srcPortBytes[1]; // Source port low byte
            udpHeader[2] = destPortBytes[0]; // Destination port high byte
            udpHeader[3] = destPortBytes[1]; // Destination port low byte

            ushort udpLength = (ushort)(8); // UDP header length (8 bytes)
            udpHeader[4] = (byte)(udpLength >> 8); // High byte
            udpHeader[5] = (byte)(udpLength & 0xFF); // Low byte

            // Checksum (optional for UDP, set to 0)
            udpHeader[6] = 0x00;
            udpHeader[7] = 0x00;
            return udpHeader;
        }

        // Create TCP header
        private byte[] CreatetcpUdpHeader(byte[] destPortBytes, byte[] srcPortBytes) {
            byte[] tcpUdpHeader = new byte[20];
            tcpUdpHeader[0] = srcPortBytes[0]; // High byte of source port
            tcpUdpHeader[1] = srcPortBytes[1]; // Low byte of source port
            tcpUdpHeader[2] = destPortBytes[0]; // High byte of destination port
            tcpUdpHeader[3] = destPortBytes[1]; // Low byte of destination port
            tcpUdpHeader[4] = 0x00; // Sequence number
            tcpUdpHeader[5] = 0x00; // Sequence number
            tcpUdpHeader[6] = 0x00; // Sequence number
            tcpUdpHeader[7] = 0x00; // Sequence number
            tcpUdpHeader[8] = 0x00; // Acknowledgment number
            tcpUdpHeader[9] = 0x00; // Acknowledgment number
            tcpUdpHeader[10] = 0x00; // Acknowledgment number
            tcpUdpHeader[11] = 0x00; // Acknowledgment number
            tcpUdpHeader[12] = 0x50; // Data offset and reserved
            tcpUdpHeader[13] = 0x02; // Flags (SYN)
            tcpUdpHeader[14] = 0x04; // Window size
            tcpUdpHeader[15] = 0x00; // Window size
            tcpUdpHeader[16] = 0x00; // Checksum (to be filled later)
            tcpUdpHeader[17] = 0x00; // Checksum (to be filled later)
            tcpUdpHeader[18] = 0x00; // Urgent pointer
            tcpUdpHeader[19] = 0x00; // Urgent pointer
            return tcpUdpHeader;
        }

    }
}