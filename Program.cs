using System;
using CommandLine;

namespace proj1
{
    class Program
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<ArgsOptions>(args)
            .WithParsed(options =>
            {
                if (string.IsNullOrEmpty(options.Interface) && string.IsNullOrEmpty(options.Target))
                {
                    Console.WriteLine("Listing active interfaces...");
                    
                    return;
                }

                Console.WriteLine($"Interface: {options.Interface ?? "None"}");
                Console.WriteLine($"TCP Ports: {options.TcpPorts ?? "None"}");
                Console.WriteLine($"UDP Ports: {options.UdpPorts ?? "None"}");
                Console.WriteLine($"Timeout: {options.Timeout} ms");
                Console.WriteLine($"Target: {options.Target ?? "None"}");

                
            })
            .WithNotParsed(errors =>
            {
                Console.WriteLine("Invalid arguments provided.");
                foreach (var error in errors)
                {
                    Console.WriteLine(error.ToString());
                }
            });
        }
    }
}
