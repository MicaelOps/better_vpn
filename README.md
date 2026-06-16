VPN Project

-> better_vpn_user = Starts the kernel driver and registers the filters

-> better_vpn = Implements redirection and encryption

-> better_vpn_server = The Proxy, receives the packets from the better_vpn_user and acts as the middle man

Logs (rants, vents and afterthoughts):

16/06/2026
- I got the job and started 5th May. Additionally, with my first salary, I purchased a laptop just for Linux. Therefore, it will be hard to continue the window side of things as I performed a full reset on my previous one.
  
17/04/2026
- I've finished my final interview, not sure if i will get accepted. Not the cleanest perfomance.
- Oh well, at least im back for this project.

08/04/2026
- Holy, I had a nice 1st stage, havent received an email about the 2nd stage.
- But the prep I am doing is making me learn alot. I will have a lot of changes once everything is over 

27/03/2026
- I will have to take a break here because I have to study for my interview and pretty much have to revise my basics.
- Potentially, I will add a few more fixes.

25/03/2026
- God, why have you made me this stupid? Is this punishment from my last life's actions?
- I was using the wrong POOL_FLAG in ExAllocatePool2. Instead of "NonPagedPool" I had to use POOL_FLAGS_NON_PAGED

23/03/2026
- Undergoing tests, for some reason ExAllocatePool2 is failing.
- I wish I could write more for this log but I am so sleep and its only 6pm.

22/03/2026
- Omg, I might have overthought. After reading the docs again and again, it kinda clicked on what to do.
- Even though I am happy with the progress, I haven't tested anything yet. Therefore, the hardest part hasn't even been crossed
- The recv() part is gonna be interesting because it is part of the better_vpn_server but I dont think I have to do much because the socket is linked to the server and not the original address hence I don't actually need to do anything.
- Only the send() is a little bit complex because I have to add the vpn header of "this is the original address and port".

21/03/2026
- Took some steps towards modification of tcp packets 
- I have no idea how am I going to modify the NET_BUFFER_LIST, it looks hella complicated whenever I look at the docs.
- I will leave the problem for tomorrow's me
20/03/2026
- Doing some work now! Finished setting up the layer to modify the packets before is sent out to the VPN Server.
- I still have to finish on the drivers side but it should be fine.
- I am a bit upset that you cant associate the same context between different callouts. Dont they all kinda belong to the same socket handle?
- Also, so sad that C doesnt have dictionary like in c++. Thank the lord for the RTL windows functions.

19/03/2026
- god, long time no see
- I really need a new laptop, running a vm that is not slow hurts my pc so much. 
- Anyways, after creating a new vm with more space, I was able to install wireshark and setup a simple server to receive the redirected packets. After testing everything, the packets were being redirected! Hooray!
- Now the final stage of the VPN are here. Which are:
- How does the vpn server interpret the redirected packets
- How does the vpn server reply back?
- I know that I can add context to the connections, hence I will be able to manipulate the connection information.
- Now I may have to add another layer to filter the send() data to add the extra details for the vpn server
- And potentially filter the recv() to receive the correct that as the vpn server could be sending multiple packets for different destinations.
- But overrall, not bad.

24/01/2026
- Damn, I fixed alot of things around the redirecting but it is still not redirecting to the correct address (routing issues?)
- I have to try redirect to an outside server and install wireshark on the vm.

20/01/2026
- NICE!!! WE ARE REDIRECTING!!! 
- However, I think we are redirecting everything, and when i mean everything, i really mean everything.
- I cant ping, i cant access websites i cant do anything.

18/01/2026
- omg i just noticed ive been putting 2025 in my timestamps
- I am very close to successfully redirect the packets.
- However ive been glitching the Windows VM too often and its making the experience soo tiring.

17/01/2026
- We reached our first Blue Scren of Death!! Very exciting!
- Now we have to debug the kernel like pros! 


12/01/2026
- we are so back, we are finishing this.
- Instead of trying to cast SOCKADDR_STORAGE from a SOCKADDR struct why not just copy and write memory directly?
- Feels sketchy but thats just C? Anyways, haven't tested but its gonna fail. 100%.
- Maybe this is why AI is gonna be amazing, i just need to think of great ideas and not care too much about production.

26/12/2025
- Okkkk, welcome back myself to this project after a suboptimal grind of leetcode (ive only done like 3 easy-medium dynamic programming exercises)
- A little bit out of touch so I will just do the server bit which is the easiest to do.
- It literally is just receiving the connections like I did in the Minecraft Server, get the packet data which contains the actual inteded destination and parameters and do the connection!
- Although, I realised I might need to perform a in-depth inspection to avoid sending the IP Address over packet data. (like programs obtaining from the application layer)

18/12/2025
- My brothers in Christ. I legit don't know how to set the remote address to my specific address.
- MSDN docs says that I should use INET_SETADDRESS but that macro doesnt even exist!! WTF?
- Now im trying to unsuccessfully send a sockaddr obtained from getaddrinfo to cast it to SOCKADDR_STORAGE which is not working.
- Is asking AI my last resort? Lets give it a few more tries...


13/12/2025
- Started grinding Leetcode (again) so I can start applying for jobs. Therefore, I will not have alot of time for cooler things like this.
- Kinda hard juggling between my full-time useless admin job, programming my FUN projects, my other hobbies (piano,novels,gaming, etc), grinding leetcode
- Holy mother god, this final redirection part from the client side is bugging me out. I have seen the example from the docs but even then...
- I will give it a try again tomorrow...

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
