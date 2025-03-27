using System;
using CommandLine;
using System.Net.NetworkInformation;



namespace proj1
{
    class Program
    {
        static void Main(string[] args)
        {
            // parsing arguments
            ScanParams scanParams = null;
            Parser.Default.ParseArguments<ArgsOptions>(args)
            .WithParsed(options =>
            {


                 // check if help flag is set
                if (options.Help)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("  -i, --interface <name>    Specify network interface");
                    Console.WriteLine("  -u, --pu <ports>         UDP ports to scan");
                    Console.WriteLine("  -t, --pt <ports>         TCP ports to scan");
                    Console.WriteLine("  -w, --wait <ms>         Timeout in milliseconds (default is 5000ms)");
                    Console.WriteLine("  <target>                Target domain or IP address");
                    Environment.Exit(0);
                }
                

                // if interface or target is not set
                if (string.IsNullOrEmpty(options.Interface) || string.IsNullOrEmpty(options.Target) || (string.IsNullOrEmpty(options.TcpPorts) && string.IsNullOrEmpty(options.UdpPorts))) {
                    // print list of active interfaces
                    Console.WriteLine("Listing active interfaces...");

                    var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                    foreach (var ni in interfaces)
                    {
                        Console.WriteLine($"Name: {ni.Name}, Description: {ni.Description}, Status: {ni.OperationalStatus}");
                    }
                    Environment.Exit(1);
                }

                // create OOP representation of the command line arguments
                scanParams = new ScanParams
                (
                    networkInterface: options.Interface,

                    // if udp/tcp ports null, create empty list
                    tcpPorts: string.IsNullOrEmpty(options.TcpPorts) ? new List<string>() : FillPortsList(options.TcpPorts),
                    udpPorts: string.IsNullOrEmpty(options.UdpPorts) ? new List<string>() : FillPortsList(options.UdpPorts),

                    target: options.Target,
                    timeout: options.Timeout
                );

                
            })
            // arguments parsing error
            .WithNotParsed(errors =>
            {
                Console.Error.WriteLine("Parsing args error");
                Environment.Exit(1);   
            });

        
            // scan tcp ports    
            scanParams.ScanTcpPorts();
            // scan udp ports
            scanParams.ScanUdpPorts();
            
            

        }
        // function parsed port numbers to list of tcp and udp ports
        private static List<string> FillPortsList(string ports)
        {
            List<string> portsList = new List<string>();
            
            var portSegments = ports.Split(',');
            foreach (var segment in portSegments)
            {
                if (segment.Contains("-"))
                {
                    var portRange = segment.Split('-');
                    int startPort = int.Parse(portRange[0]);
                    int endPort = int.Parse(portRange[1]);

                    for (int port = startPort; port <= endPort; port++)
                    {
                        portsList.Add(port.ToString());
                    }
                }
                else
                {
                    portsList.Add(segment);
                }
            }
            return portsList;
        }
    }
}
