#!/bin/bash

echo "My script:"
dotnet run --interface enp0s3 -t 21,22,80,143,443 45.33.32.156
echo "Nmap":
nmap -sS -p 21,22,80,143,443 45.33.32.156

