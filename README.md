VPN Project

-> better_vpn_user = Starts the driver and registers the filters

-> better_vpn_driver = Implements the big boy's redirection and encryption

-> better_vpn_server (to be created) = the middleman

Logs (rants, vents and afterthoughts):

08/12/2025
- Even though I have been abusing WFP, Im starting to wonder how difficult would it be to use NDIS. Some cool stuff could have been done there.
- I would like to find out why other VPNs use a virtual network interface (TAP adapter). Ethernet? Control? Overhead issues? Efficiency? Visbility? WFP/NDIS seem to provide enough.
- IDK, I am the clueless one.

07/12/2025
- God, I fixed the issue of the better_vpn_user project not showing up in git. Wasnt hard at all! More git pushes will start showing up.
- Have been doing heavy reading on the ClassifyFn of the Callout Driver because it appears to be where magic happens.
- Only to find out that I have to go back to usermode to implement filter layers so it can communicate with my callout driver. Understandable dynamic but aaaah.
- At some point if i get bored of writing the vpn, I will just jump to the server part of the vpn for more fun. 
- Also, hella scary how these applications can literally store ALL your network communication at will and we will never know about it until its leaked or someone decided to act as a crusader.
- I will most likely never use a VPN ever again, unless it is to marvel at the wonders of yin-yang. All hail TOR.


05/12/2025
- Finally finished the user side load of the driver.
- Almost got illness understanding why my driver was not loading even though manually was working.
- There are no updates here as this is only the kernel project. Idk why visual studio grief me like this even though they are on the same solution.

01/12/2025
- Added some basic IRP handling, still need to add a few more touches.
- I will probably continue doing the WFP code after confirming that I can communicate with the driver through user mode.
- Exciting Stuff !! 

30/11/2025

- Been reading alot of NDIS and WFP, I accidently started using the WFP user mode functions inside the kernel driver instead of the kernel functions
- It was hell setting up my VM to test the kernel driver


27/11/2025

- Okkkk, procrastinating from Minecraft Server to do this epic thing of creating VPN, and later on, a Nginx like application for the Minecraft Server
- Barely worked with Kernel drivers but we will make it work somehow.