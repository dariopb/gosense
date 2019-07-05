# gosense
gosense is a golang library implementing the communication protocol used by the WyzeSense USB dongle: https://support.wyzecam.com/hc/en-us/categories/360001610132-Wyze-Sense. The Wyze products, hardware and software, are great and super affordable and they have a bunch of options to integrate with 3rd party offerings (IFTTT, Alexa, Google Home Assistant) but all those integrations require the sensors to be "connected" to the cloud for the messages to get relayed, if there is no internet connectivity you are out of luck. Hence the first goal of this project: to be able to get the dongle and the sensors to communicate state in a local network, with the dongle attached to a generic Linux machine or raspberry pi .

 The second goal of this library is to serve as a base for integrating the WyzeSense sensors into high level home automation products (chiefly HA via MQTT for now).

Currently, the Wyze dongle is showing up as a raw HID device, only accessible by the root account so you'll have to run the calling code as root or chmod the device where the dongle is attached (/dev/hidraw0 for example)" so regular user accounts can read/write to it.

For an application that uses this library to discovery and publish sensor actions to HA via the HA MQTT Discovery mechanism, please look here: https://github.com/dariopb/ha-gosenseapp 

I started reverse engineering the sense but HclX beat me by a week or so, so this work is based largely on the info and reverse eng effort he did! His python script from https://github.com/HclX/WyzeSensePy and blog post here: https://hclxing.wordpress.com/2019/06/06/reverse-engineering-wyzesense-bridge-protocol-part-iii/ are good reads!
