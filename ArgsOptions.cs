using CommandLine;

namespace proj1
{
    class ArgsOptions
    {
        [Option('i', "interface", Required = false, HelpText = "Specify network interface (e.g., eth0). If omitted, lists active interfaces.")]
        public string? Interface { get; set; }

        [Option('u', "pu", Required = false, HelpText = "UDP ports to scan (e.g., 53,67 or 1-65535).")]
        public string? UdpPorts { get; set; }

        [Option('t', "pt", Required = false, HelpText = "TCP ports to scan (e.g., 22,23,24 or 1-65535).")]
        public string? TcpPorts { get; set; }

        [Option('w', "wait", Required = false, Default = 5000, HelpText = "Timeout in milliseconds for each port scan.")]
        public int Timeout { get; set; }

        [Value(0, MetaName = "target", Required = false, HelpText = "Target domain name or IP address to scan.")]
        public string? Target { get; set; }
    }
}
