# dotnet-matter
Perform Matter device commissioning and control using .Net

I'm not sure this can even be made to work, but I'd love to be able to perform some basic commissioning of Matter devices using .Net

There are a few pieces to get working.

#1 using Bluetooth to connect to the device for commissioning.

#2 Connect to the device

#3 Connect it to a network (WiFi or Thread)

#4 Find it after connection

#5 Connect to the device

## Notes

### 25/02 

The first step is decoding the commissioning code which contains the information about the device. If we look at the Nordic Light Switch sample (https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.2.99-dev3/nrf/samples/matter/light_switch/README.html), you'll see they provide onboarding information. This is in the form of a QR code. It contains 
information about the device, including it's setup code. 

The first step for my commissioner is to take the manual pairing code, parse it and then use Bluetooth to find the device.

I downloaded the Matter 1.0 Core specification and, in Chapter 5, it runs through the Onboarding Payload.

08:52
First new thing for me - What the heck is Base38 encoding??

