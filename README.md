# dotnet-matter

A Matter controller written in .Net Core

I'm not sure this can even be made to work, but I'd love to be able to perform some basic commissioning of Matter devices using .Net

There are a few milestones I want to accomplish.

- Parsing a setup code to extract the pin and discriminator
- Finding a device using Bluetooth
- Establishing a secure connection to that device
- Adding it to a network (WiFi or Thread) - I feel Wifi is probably the easiest to start!
- Sending simple commands to the device.
- Binding the device to another device.
- Unpairing with the device.
 
## Progress Log

I'm going to try and keep a progress log going here. I've done quite a bit already at this point however, so those steps are lost to the mists of time.

The first step is decoding the commissioning code which contains the information about the device. If we look at the Nordic Light Switch sample (https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.2.99-dev3/nrf/samples/matter/light_switch/README.html), you'll see they provide onboarding information. This is in the form of a QR code. It contains information about the device, including it's setup code. 

The first step for my commissioner is to take the manual pairing code, parse it and then use Bluetooth to find the device using the Discriminator.

> [!Note]
> The blog posts will represent points in time as I add and explore the protocol. The whole framework will evolve, so the code in the posts will go out of date, but the technicals will still be useful to look at.

10/06/2025

Add some simple reconnection logic to the MatterController. It also introduces the https://github.com/tomasmcguinness/dotnet-matter-controller project

https://tomasmcguinness.com/2025/06/10/building-a-net-matter-controller-simple-reconnection/

12/05/2025

Successfully finished the Commissioning project by having a CommissioningComplete Command accepted by a matter.js example device! I've tagged the report with v0.1

* https://tomasmcguinness.com/2025/05/12/building-a-net-matter-controller-commissioning-flow-commissioningcomplete/

10/05/2025

Created a CASE Secure Session today. This meant generating & handling the Sigma1, Sigma2 and Sigma3 messages! 

* https://tomasmcguinness.com/2025/05/10/building-a-net-matter-controller-commissioning-flow-case-pt1-2/

### 07/05/2025

Figured out how to generated a Root CA certificate and managed to get the AddNOC command working too. THe matter.js example device is now creating a fabric!

* https://tomasmcguinness.com/2025/05/07/building-a-net-matter-controller-commissioning-flow-certificates-pt3/

### 04/05/2025

AddTrustedRootCertificate command *finally* accepted by matter.js. I'm only using the example cert from the Matter Specification, but it's working nonetheless!

* https://tomasmcguinness.com/2025/04/30/building-a-net-matter-controller-commissioning-flow-case-pt1/
* https://tomasmcguinness.com/2025/05/04/building-a-net-matter-controller-commissioning-flow-case-pt2/

### 27/04/2025

Another milestone reached. My .Net Controller has exchanged a PASE encrypted message with a matter.js example device, successfully retrieving the vendor name attribute! I also started on a UDP controller, with some mDNS support. https://tomasmcguinness.com/2025/04/27/building-a-net-matter-controller-commissioning-flow-get-basic-information/

### 16/04/2025

First milestone reached! I have successfully exchanged the PASE messages. I ended up running the matter.js project and adding lots of logging to help me troubleshoot my code. In the end, I was 99% the way there, but my Transcript Hash was wrong, because of two mistakes in my code. You can read all about it here: https://tomasmcguinness.com/2025/04/15/building-a-net-matter-controller-commissioning-flow-pase-pt4/.
I'm now starting to look at how to use these PASE keys to speak in a secured way to the device. 

### 02/04/2025

Lots of progress in the past two weeks. I have successfully sent one of the PASE messages (PBKDFParamRequest) and received a response with some of the parameters present (PBKDFParamResponse)
I am now trying to get the Pake1 message working. As this involved crytography, it's proving very difficult! All detailed in these posts:

* https://tomasmcguinness.com/2025/04/12/building-a-net-matter-controller-commissioning-flow-pase-pt2/
* https://tomasmcguinness.com/2025/04/12/building-a-net-matter-controller-commissioning-flow-pase-pt3/

### 21/03/2025

I picked this project up again as I've been playing a lot with ESP32 and Matter. A year later to the day.
I have gotten Bluetooth scanning working, uwing the WinRT Bluetooth libraries. This will limit it to Windows 10 for now, but that's okay for now. I've written a blog post on this: https://tomasmcguinness.com/2025/03/21/building-a-net-matter-controller/
I have also managed to establish a BTP (Bluetooth Transport Protocol) session, getting a handshake reponse from an ESP32-C6 (running the esp-matter Light example). 

### 21/03/2024

At this point, I have written some basic code that accepts a manual pairing code and parses it to exact the discriminator and setup code. It then starts watching for BLE devices. It parses the advertising payloads of the all the BLE devices it finds. The discriminator value is pulled out and compared to the one provided by the manual pairing code. This isn't correct to the specification, since I'm assuming that the 4 version bits are always zero.



