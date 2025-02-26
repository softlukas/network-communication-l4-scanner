using System;
using System.Collections.Generic;

namespace proj1
{
    class ScanParams
    {
        public string? NetworkInterface { get; private set; }
        public List<string> UdpPorts { get; private set; }
        public List<string> TcpPorts { get; private set; }
        public string? Target { get; private set; }

        public ScanParams(string? networkInterface, List<string> udpPorts, List<string> tcpPorts, string? target)
        {
            NetworkInterface = networkInterface;
            UdpPorts = udpPorts;
            TcpPorts = tcpPorts;
            Target = target;
        }

    
    }
}