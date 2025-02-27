using System;
using System.Collections.Generic;

namespace proj1
{
    class ScanParams
    {
        public string? NetworkInterface { get; private set; }
        public List<string> UdpPorts { get; private set; }
        public List<string> TcpPorts { get; private set; }
        public string? TargetIp { get; private set; }
        public byte[] SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public byte[] TargetMac { get; private set; }

        public ScanParams(string? networkInterface, List<string> udpPorts, List<string> tcpPorts, 
        string? targetIp, byte[] sourceIp, byte[] sourceMac, byte[] targetMac)
        {
            NetworkInterface = networkInterface;
            UdpPorts = udpPorts;
            TcpPorts = tcpPorts;
            TargetIp = targetIp;
            SourceIp = sourceIp;
            SourceMac = sourceMac;
        }

        public void SendSynPacket() {
            
        }

    
    }
}