using System;
using System.Net;

namespace proj1 {

    class Packet {

        public ushort DestPort { get; private set; }
        public ushort SrcPort { get; private set; }
        public byte[] SourceIp { get; private set; }
        public string TargetIp { get; private set; }
        
        

        public Packet(ushort destPort, ushort srcPort, byte[] sourceIp, string targetIp) {
            DestPort = destPort;
            SrcPort = srcPort;
            SourceIp = sourceIp;
            TargetIp = targetIp;

        }

        public byte[] BuildPacket() {
            // set destination port
            byte[] destPortBytes = SetPortBytes(DestPort);

            byte[] SrcPortBytes = SetPortBytes(SrcPort);
            
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
            Array.Copy(IPAddress.Parse(TargetIp).GetAddressBytes(), 0, ipHeader, 16, 4); 

            // Recalculate IP header checksum
            ushort ipChecksum = CalculateChecksum(ipHeader);
            ipHeader[10] = (byte)(ipChecksum >> 8);
            ipHeader[11] = (byte)(ipChecksum & 0xFF);

            // Create TCP header
            byte[] tcpHeader = new byte[20];
            
            tcpHeader[0] = SrcPortBytes[0]; // High byte of source port
            tcpHeader[1] = SrcPortBytes[1]; // Low byte of source port
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
            Array.Copy(IPAddress.Parse(TargetIp).GetAddressBytes(), 0, pseudoHeader, 4, 4); 
            pseudoHeader[8] = 0x00; // Reserved
            pseudoHeader[9] = 0x06; // Protocol (TCP)


            pseudoHeader[10] = (byte)(tcpHeader.Length >> 8);
            pseudoHeader[11] = (byte)(tcpHeader.Length & 0xFF);

            Array.Copy(tcpHeader, 0, pseudoHeader, 12, tcpHeader.Length);


            ushort tcpChecksum = CalculateChecksum(pseudoHeader);
            tcpHeader[16] = (byte)(tcpChecksum >> 8);
            tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

            // Combine IP and TCP headers into a single packet
            byte[] packet = new byte[ipHeader.Length + tcpHeader.Length];
            Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
            Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);

            return packet;
        }

        private byte[] SetPortBytes(ushort port) {
            byte[] portBytes = BitConverter.GetBytes(port);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(portBytes);
            }
            return portBytes;
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