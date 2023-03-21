# dotnet-matter
Perform Matter device commissioning and control using .Net

I'm not sure this can even be made to work, but I'd love to be able to perform some basic commissioning of Matter devices using .Net

There are a few pieces to get working.

#1 using Bluetooth to connect to the device for commissioning.

#2 Connect to the device

#3 Connect it to a network (WiFi or Thread)

#4 Find it after connection

#5 Connect to the device

## Progress Log

I'm going to try and keep a progress log going here. I've done quite a bit already at this point however, so those steps are lost to the mists of time.

The first step is decoding the commissioning code which contains the information about the device. If we look at the Nordic Light Switch sample (https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.2.99-dev3/nrf/samples/matter/light_switch/README.html), you'll see they provide onboarding information. This is in the form of a QR code. It contains information about the device, including it's setup code. 

The first step for my commissioner is to take the manual pairing code, parse it and then use Bluetooth to find the device using the Discriminator.

## 21/03 
At this point, I have written some basic code that accepts a manual pairing code and parses it to exact the discriminator and setup code. It then starts watching for BLE devices. It parses the advertising payloads of the all the BLE devices it finds. The discriminator value is pulled out and compared to the one provided by the manual pairing code. This isn't correct to the specification, since I'm assuming that the 4 version bits are always zero.





