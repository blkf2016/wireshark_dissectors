--[[
Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.2

Copyright (c) 2017 Daniele Palmas <dnlplm@gmail.com>

Based on:

- Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.1
  Copyright (c) 2012 Ilya Voronin <ivoronin@gmail.com>
  found at: https://gist.github.com/ivoronin/2641557

- Code Aurora Forum's BSD/GPL licensed code:
  http://www.codeaurora.org/contribute/projects/gobi/

- freedesktop.org libqmi
  https://www.freedesktop.org/wiki/Software/libqmi/

How to use the dissector:

LINUX

1. Make sure to have usbmon support enabled

2. Find device in the lsusb output, e.g.:

    $ lsusb
    ...
    Bus 003 Device 022: ID 1bc7:1201 Telit Wireless Solutions
    ...

3. Run wireshark:

    $ wireshark -X lua_script:qmi_dissector_gen.lua

4. Collect log in the appropriate usbmon device (3 in the example) and appply qmi filter

WINDOWS

1. Make sure to have usbpcap installed

2. Find device in USBPcapCMD.exe output, e.g.:

    C:\Program Files\USBPcap\USBPcaCMD.exe
    ...
    2 \\.\USBPcap4
      \??\USB#ROOT_HUB20#4&244e1552&0#<f18a0e88-c30c-11d0-8815-00a0c906bed8>
        [Port 2] Telit USB  Composite Device 0x1201

3. Run wireshark:

    "C:\Program Files\Wireshark\Wireshark.exe" -X lua_script:qmi_dissector_gen.lua

4. Collect log in the appropriate usbpcap device (4 in the example)

--]]

---
--- Proto declaration
---
qmi_proto = Proto("qmi", "Qualcomm MSM Interface")

--
-- Fields
--
local f = qmi_proto.fields

-- QMUX Header
f.tf =        ProtoField.uint8("qmi.tf", "T/F", base.DEC)
f.len =       ProtoField.uint16("qmi.len", "Length", base.DEC)
f.flag =      ProtoField.uint8("qmi.flag", "Flag", base.HEX)
f.cid =       ProtoField.uint8("qmi.cliend_id", "Client ID", base.HEX)
-- Transaction Header
f.resp_ctl =  ProtoField.uint8("qmi.trans_response", "Transaction Response Bit",
				base.DEC, nil, 1)
f.ind_ctl =   ProtoField.uint8("qmi.trans_indication", "Transaction Indication Bit",
				base.DEC, nil, 2)
f.comp_svc =  ProtoField.uint8("qmi.trans_compound", "Transaction Compound Bit",
				base.DEC, nil, 1)
f.resp_svc =  ProtoField.uint8("qmi.trans_response", "Transaction Response Bit",
				base.DEC, nil, 2)
f.ind_svc =   ProtoField.uint8("qmi.trans_indication", "Transaction Indication Bit",
				base.DEC, nil, 4)
f.tid_ctl =   ProtoField.uint8("qmi.trans_id", "Transaction ID", base.HEX)
f.tid_svc =   ProtoField.uint16("qmi.trans_id", "Transaction ID", base.HEX)
-- Message Header
f.msgid =     ProtoField.uint16("qmi.message_id", "Message ID", base.HEX)

services = { [16] = "loc", [9] = "voice", [4] = "qos", [26] = "wda", [5] = "wms", [11] = "uim", [6] = "pds", [14] = "rmtfs", [7] = "auth", [3] = "nas", [10] = "cat2", [1] = "wds", [8] = "at", [17] = "sar", [0] = "ctl", [12] = "pbm", [2] = "dms", [36] = "pdc",  }

f.svcid =     ProtoField.uint8("qmi.service_id", "Service ID", base.HEX, services)
qos_messages  = { [0x0000] = "Reset", [0x0026] = "Get Flow Status", [0x0027] = "Get Network Status", [0x5556] = "Swi Read Data Stats",  }

f.msgid_qos = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, qos_messages)

tlv_qos_req = { [0x0000] = { }, [0x0026] = { [0x01] = 'Qos Id', }, [0x0027] = { }, [0x5556] = { [0x01] = 'Apn Id', }, }

tlv_qos_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0026] = { [0x02] = 'Result', [0x01] = 'Value', }, [0x0027] = { [0x02] = 'Result', [0x01] = 'QoS Supported', }, [0x5556] = { [0x02] = 'Result', [0x03] = 'Apn', [0x04] = 'Flow', }, }

qos_indications = { [0x0026] = "Flow Status", [0x0027] = "Network Status", }

tlv_qos_ind = { [0x0026] = { [0x01] = 'Value', }, [0x0027] = { [0x01] = 'QoS Supported', }, }

pbm_messages  = { [0x0001] = "Indication Register", [0x0002] = "Get Capabilities", [0x0003] = "Get All Capabilities",  }

f.msgid_pbm = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, pbm_messages)

tlv_pbm_req = { [0x0001] = { [0x01] = 'Event Registration Mask', }, [0x0002] = { [0x01] = 'Phonebook Information', }, [0x0003] = { }, }

tlv_pbm_resp = { [0x0001] = { [0x02] = 'Result', [0x10] = 'Event Registration Mask', }, [0x0002] = { [0x02] = 'Result', [0x10] = 'Capability Basic Information', [0x11] = 'Group Capability', [0x12] = 'Additional Number Capability', [0x13] = 'Email Capability', [0x14] = 'Second Name Capability', [0x15] = 'Hidden Records Capability', [0x16] = 'Grouping Information Alpha String Capability', [0x17] = 'Additional Number Alpha String Capability', }, [0x0003] = { [0x02] = 'Result', [0x10] = 'Capability Basic Information', [0x11] = 'Group Capability', [0x12] = 'Additional Number Capability', [0x13] = 'Email Capability', [0x14] = 'Second Name Capability', [0x15] = 'Hidden Records Capability', [0x16] = 'Grouping Information Alpha String Capability', [0x17] = 'Additional Number Alpha String Capability', }, }

pbm_indications = { }

tlv_pbm_ind = { }

wms_messages  = { [0x0000] = "Reset", [0x0001] = "Set Event Report", [0x001E] = "Get Supported Messages", [0x0020] = "Raw Send", [0x0021] = "Raw Write", [0x0022] = "Raw Read", [0x0023] = "Modify Tag", [0x0024] = "Delete", [0x0030] = "Get Message Protocol", [0x0031] = "List Messages", [0x0032] = "Set Routes", [0x0033] = "Get Routes", [0x0042] = "Send From Memory Storage",  }

f.msgid_wms = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, wms_messages)

tlv_wms_req = { [0x0000] = { }, [0x0001] = { [0x10] = 'New MT Message Indicator', }, [0x001E] = { }, [0x0020] = { [0x01] = 'Raw Message Data', [0x10] = 'CDMA Force On DC', [0x11] = 'CDMA Follow On DC', [0x12] = 'GSM WCDMA Link Timer', [0x13] = 'SMS on IMS', }, [0x0021] = { [0x01] = 'Raw Message Data', }, [0x0022] = { [0x01] = 'Message Memory Storage ID', [0x10] = 'Message Mode', [0x11] = 'SMS on IMS', }, [0x0023] = { [0x01] = 'Message Tag', [0x10] = 'Message Mode', }, [0x0024] = { [0x01] = 'Memory Storage', [0x10] = 'Memory Index', [0x11] = 'Message Tag', [0x12] = 'Message Mode', }, [0x0030] = { }, [0x0031] = { [0x01] = 'Storage Type', [0x11] = 'Message Tag', [0x12] = 'Message Mode', }, [0x0032] = { [0x01] = 'Route List', [0x10] = 'Transfer Status Report', }, [0x0033] = { }, [0x0042] = { [0x01] = 'Information', [0x10] = 'SMS on IMS', }, }

tlv_wms_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0001] = { [0x02] = 'Result', }, [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x0020] = { [0x02] = 'Result', [0x01] = 'Message ID', [0x10] = 'CDMA Cause Code', [0x11] = 'CDMA Error Class', [0x12] = 'GSM WCDMA Cause Info', [0x13] = 'Message Delivery Failure Type', }, [0x0021] = { [0x02] = 'Result', [0x01] = 'Memory Index', }, [0x0022] = { [0x02] = 'Result', [0x01] = 'Raw Message Data', }, [0x0023] = { [0x02] = 'Result', }, [0x0024] = { [0x02] = 'Result', }, [0x0030] = { [0x02] = 'Result', [0x01] = 'Message Protocol', }, [0x0031] = { [0x02] = 'Result', [0x01] = 'Message List', }, [0x0032] = { [0x02] = 'Result', }, [0x0033] = { [0x02] = 'Result', [0x01] = 'Route List', [0x10] = 'Transfer Status Report', }, [0x0042] = { [0x02] = 'Result', [0x10] = 'Message ID', [0x11] = 'CDMA Cause Code', [0x12] = 'CDMA Error Class', [0x13] = 'GSM WCDMA Cause Info', [0x14] = 'Message Delivery Failure Type', }, }

wms_indications = { [0x0001] = "Event Report", [0x0046] = "SMSC Address", }

tlv_wms_ind = { [0x0001] = { [0x10] = 'MT Message', [0x11] = 'Transfer Route MT Message', [0x12] = 'Message Mode', [0x13] = 'ETWS Message', [0x14] = 'ETWS PLMN Information', [0x15] = 'SMSC Address', [0x16] = 'SMS on IMS', }, [0x0046] = { [0x01] = 'Address', }, }

wds_messages  = { [0x0000] = "Reset", [0x0001] = "Set Event Report", [0x0002] = "Abort", [0x001E] = "Get Supported Messages", [0x0020] = "Start Network", [0x0021] = "Stop Network", [0x0022] = "Get Packet Service Status", [0x0023] = "Get Channel Rates", [0x0024] = "Get Packet Statistics", [0x0025] = "Go Dormant", [0x0026] = "Go Active", [0x0027] = "Create Profile", [0x0028] = "Modify Profile", [0x0029] = "Delete Profile", [0x002A] = "Get Profile List", [0x002B] = "Get Profile Settings", [0x002C] = "Get Default Settings", [0x002D] = "Get Current Settings", [0x0030] = "Get Dormancy Status", [0x0034] = "Get Autoconnect Settings", [0x0037] = "Get Data Bearer Technology", [0x0044] = "Get Current Data Bearer Technology", [0x0049] = "Get Default Profile Num", [0x004A] = "Set Default Profile Num", [0x004D] = "Set IP Family", [0x0051] = "Set Autoconnect Settings", [0x006C] = "Get PDN Throttle Info", [0x00A2] = "Bind Mux Data Port", [0x5558] = "Swi Create Profile Indexed",  }

f.msgid_wds = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, wds_messages)

tlv_wds_req = { [0x0000] = { }, [0x0001] = { [0x10] = 'Channel Rate', [0x11] = 'Transfer Statistics', [0x12] = 'Data Bearer Technology', [0x13] = 'Dormancy Status', [0x14] = 'MIP Status', [0x15] = 'Current Data Bearer Technology', [0x17] = 'Data Call Status', [0x18] = 'Preferred Data System', [0x19] = 'EVDO PM Change', [0x1A] = 'Data Systems', [0x1B] = 'Uplink Flow Control', [0x1C] = 'Limited Data System Status', [0x1D] = 'PDN Filter Removals', [0x1E] = 'Extended Data Bearer Technology', }, [0x0002] = { [0x01] = 'Transaction ID', }, [0x001E] = { }, [0x0020] = { [0x10] = 'Primary DNS Address Preference', [0x11] = 'Secondary DNS Address Preference', [0x12] = 'Primary NBNS Address Preference', [0x13] = 'Secondary NBNS Address Preference', [0x14] = 'APN', [0x15] = 'IPv4 Address Preference', [0x16] = 'Authentication Preference', [0x17] = 'Username', [0x18] = 'Password', [0x19] = 'IP Family Preference', [0x30] = 'Technology Preference', [0x31] = 'Profile Index 3GPP', [0x32] = 'Profile Index 3GPP2', [0x33] = 'Enable Autoconnect', [0x34] = 'Extended Technology Preference', [0x35] = 'Call Type', }, [0x0021] = { [0x01] = 'Packet Data Handle', [0x10] = 'Disable Autoconnect', }, [0x0022] = { }, [0x0023] = { }, [0x0024] = { [0x01] = 'Mask', }, [0x0025] = { }, [0x0026] = { }, [0x0027] = { [0x01] = 'Profile Type', [0x10] = 'Profile Name', [0x11] = 'PDP Type', [0x12] = 'PDP Header Compression Type', [0x13] = 'PDP Data Compression Type', [0x14] = 'APN Name', [0x15] = 'Primary IPv4 DNS Address', [0x16] = 'Secondary IPv4 DNS Address', [0x17] = 'UMTS Requested QoS', [0x18] = 'UMTS Minimum QoS', [0x19] = 'GPRS Requested QoS', [0x1A] = 'GPRS Minimum QoS', [0x1B] = 'Username', [0x1C] = 'Password', [0x1D] = 'Authentication', [0x1E] = 'IPv4 Address Preference', [0x1F] = 'PCSCF Address Using PCO', [0x21] = 'PCSCF Address Using DHCP', [0x22] = 'IMCN Flag', [0x25] = 'PDP Context Number', [0x26] = 'PDP Context Secondary Flag', [0x27] = 'PDP Context Primary ID', [0x28] = 'IPv6 Address Preference', [0x29] = 'UMTS Requested QoS With Signaling Indication Flag', [0x2A] = 'UMTS Minimum QoS With Signaling Indication Flag', [0x2B] = 'IPv6 Primary DNS Address Preference', [0x2C] = 'IPv6 Secondary DNS Address Preference', [0x2E] = 'LTE QoS Parameters', [0x2F] = 'APN Disabled Flag', [0x3E] = 'Roaming Disallowed Flag', }, [0x0028] = { [0x01] = 'Profile Identifier', [0x10] = 'Profile Name', [0x11] = 'PDP Type', [0x12] = 'PDP Header Compression Type', [0x13] = 'PDP Data Compression Type', [0x14] = 'APN Name', [0x15] = 'Primary IPv4 DNS Address', [0x16] = 'Secondary IPv4 DNS Address', [0x17] = 'UMTS Requested QoS', [0x18] = 'UMTS Minimum QoS', [0x19] = 'GPRS Requested QoS', [0x1A] = 'GPRS Minimum QoS', [0x1B] = 'Username', [0x1C] = 'Password', [0x1D] = 'Authentication', [0x1E] = 'IPv4 Address Preference', [0x1F] = 'PCSCF Address Using PCO', [0x21] = 'PCSCF Address Using DHCP', [0x22] = 'IMCN Flag', [0x25] = 'PDP Context Number', [0x26] = 'PDP Context Secondary Flag', [0x27] = 'PDP Context Primary ID', [0x28] = 'IPv6 Address Preference', [0x29] = 'UMTS Requested QoS With Signaling Indication Flag', [0x2A] = 'UMTS Minimum QoS With Signaling Indication Flag', [0x2B] = 'IPv6 Primary DNS Address Preference', [0x2C] = 'IPv6 Secondary DNS Address Preference', [0x2E] = 'LTE QoS Parameters', [0x2F] = 'APN Disabled Flag', [0x3E] = 'Roaming Disallowed Flag', }, [0x0029] = { [0x01] = 'Profile Identifier', }, [0x002A] = { [0x10] = 'Profile Type', }, [0x002B] = { [0x01] = 'Profile ID', }, [0x002C] = { [0x01] = 'Profile Type', }, [0x002D] = { [0x10] = 'Requested Settings', }, [0x0030] = { }, [0x0034] = { }, [0x0037] = { }, [0x0044] = { }, [0x0049] = { [0x01] = 'Profile Type', }, [0x004A] = { [0x01] = 'Profile Identifier', }, [0x004D] = { [0x01] = 'Preference', }, [0x0051] = { [0x01] = 'Status', [0x10] = 'Roaming', }, [0x006C] = { [0x01] = 'Network Type', }, [0x00A2] = { [0x10] = 'Endpoint Info', [0x11] = 'Mux ID', [0x13] = 'Client Type', }, [0x5558] = { [0x01] = 'Profile Identifier', [0x10] = 'Profile Name', [0x11] = 'PDP Type', [0x14] = 'APN Name', [0x15] = 'Primary IPv4 DNS Address', [0x16] = 'Secondary IPv4 DNS Address', [0x1B] = 'Username', [0x1C] = 'Password', [0x1D] = 'Authentication', [0x1E] = 'IPv4 Address Preference', [0x25] = 'PDP Context Number', [0x2F] = 'APN Disabled Flag', [0x3E] = 'Roaming Disallowed Flag', }, }

tlv_wds_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0001] = { [0x02] = 'Result', }, [0x0002] = { [0x02] = 'Result', }, [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x0020] = { [0x02] = 'Result', [0x01] = 'Packet Data Handle', [0x10] = 'Call End Reason', [0x11] = 'Verbose Call End Reason', }, [0x0021] = { [0x02] = 'Result', }, [0x0022] = { [0x02] = 'Result', [0x01] = 'Connection Status', }, [0x0023] = { [0x02] = 'Result', [0x01] = 'Channel Rates', }, [0x0024] = { [0x02] = 'Result', [0x10] = 'Tx Packets Ok', [0x11] = 'Rx Packets Ok', [0x12] = 'Tx Packets Error', [0x13] = 'Rx Packets Error', [0x14] = 'Tx Overflows', [0x15] = 'Rx Overflows', [0x19] = 'Tx Bytes Ok', [0x1A] = 'Rx Bytes Ok', [0x1B] = 'Last Call Tx Bytes Ok', [0x1C] = 'Last Call Rx Bytes Ok', [0x1D] = 'Tx Packets Dropped', [0x1E] = 'Rx Packets Dropped', }, [0x0025] = { [0x02] = 'Result', }, [0x0026] = { [0x02] = 'Result', }, [0x0027] = { [0x02] = 'Result', [0x01] = 'Profile Identifier', [0xE0] = 'Extended Error Code', }, [0x0028] = { [0x02] = 'Result', [0xE0] = 'Extended Error Code', }, [0x0029] = { [0x02] = 'Result', [0xE0] = 'Extended Error Code', }, [0x002A] = { [0x02] = 'Result', [0x01] = 'Profile List', [0xE0] = 'Extended Error Code', }, [0x002B] = { [0x02] = 'Result', [0x10] = 'Profile Name', [0x11] = 'PDP Type', [0x12] = 'PDP Header Compression Type', [0x13] = 'PDP Data Compression Type', [0x14] = 'APN Name', [0x15] = 'Primary IPv4 DNS Address', [0x16] = 'Secondary IPv4 DNS Address', [0x17] = 'UMTS Requested QoS', [0x18] = 'UMTS Minimum QoS', [0x19] = 'GPRS Requested QoS', [0x1A] = 'GPRS Minimum QoS', [0x1B] = 'Username', [0x1C] = 'Password', [0x1D] = 'Authentication', [0x1E] = 'IPv4 Address Preference', [0x1F] = 'PCSCF Address Using PCO', [0x21] = 'PCSCF Address Using DHCP', [0x22] = 'IMCN Flag', [0x25] = 'PDP Context Number', [0x26] = 'PDP Context Secondary Flag', [0x27] = 'PDP Context Primary ID', [0x28] = 'IPv6 Address Preference', [0x29] = 'UMTS Requested QoS With Signaling Indication Flag', [0x2A] = 'UMTS Minimum QoS With Signaling Indication Flag', [0x2B] = 'IPv6 Primary DNS Address Preference', [0x2C] = 'IPv6 Secondary DNS Address Preference', [0x2E] = 'LTE QoS Parameters', [0x2F] = 'APN Disabled Flag', [0x3E] = 'Roaming Disallowed Flag', [0xE0] = 'Extended Error Code', }, [0x002C] = { [0x02] = 'Result', [0x10] = 'Profile Name', [0x11] = 'PDP Type', [0x12] = 'PDP Header Compression Type', [0x13] = 'PDP Data Compression Type', [0x14] = 'APN Name', [0x15] = 'Primary IPv4 DNS Address', [0x16] = 'Secondary IPv4 DNS Address', [0x17] = 'UMTS Requested QoS', [0x18] = 'UMTS Minimum QoS', [0x19] = 'GPRS Requested QoS', [0x1A] = 'GPRS Minimum QoS', [0x1B] = 'Username', [0x1C] = 'Password', [0x1D] = 'Authentication', [0x1E] = 'IPv4 Address Preference', [0x1F] = 'PCSCF Address Using PCO', [0x21] = 'PCSCF Address Using DHCP', [0x22] = 'IMCN Flag', [0x25] = 'PDP Context Number', [0x26] = 'PDP Context Secondary Flag', [0x27] = 'PDP Context Primary ID', [0x28] = 'IPv6 Address Preference', [0x29] = 'UMTS Requested QoS With Signaling Indication Flag', [0x2A] = 'UMTS Minimum QoS With Signaling Indication Flag', [0x2B] = 'IPv6 Primary DNS Address Preference', [0x2C] = 'IPv6 Secondary DNS Address Preference', [0x2E] = 'LTE QoS Parameters', [0xE0] = 'Extended Error Code', }, [0x002D] = { [0x02] = 'Result', [0x10] = 'Profile Name', [0x11] = 'PDP Type', [0x14] = 'APN Name', [0x15] = 'Primary IPv4 DNS Address', [0x16] = 'Secondary IPv4 DNS Address', [0x17] = 'UMTS Granted QoS', [0x19] = 'GPRS Granted QoS', [0x1B] = 'Username', [0x1D] = 'Authentication', [0x1E] = 'IPv4 Address', [0x1F] = 'Profile ID', [0x20] = 'IPv4 Gateway Address', [0x21] = 'IPv4 Gateway Subnet Mask', [0x22] = 'PCSCF Address Using PCO', [0x23] = 'PCSCF Server Address List', [0x24] = 'PCSCF Domain Name List', [0x25] = 'IPv6 Address', [0x26] = 'IPv6 Gateway Address', [0x27] = 'IPv6 Primary DNS Address', [0x28] = 'IPv6 Secondary DNS Address', [0x29] = 'MTU', [0x2A] = 'Domain Name List', [0x2B] = 'IP Family', [0x2C] = 'IMCN Flag', [0x2D] = 'Extended Technology Preference', }, [0x0030] = { [0x02] = 'Result', [0x01] = 'Dormancy Status', }, [0x0034] = { [0x02] = 'Result', [0x01] = 'Status', [0x10] = 'Roaming', }, [0x0037] = { [0x02] = 'Result', [0x01] = 'Current', [0x10] = 'Last', }, [0x0044] = { [0x02] = 'Result', [0x01] = 'Current', [0x10] = 'Last', }, [0x0049] = { [0x02] = 'Result', [0x01] = 'Default Profile Number', [0xE0] = 'Extended Error Code', }, [0x004A] = { [0x02] = 'Result', [0xE0] = 'Extended Error Code', }, [0x004D] = { [0x02] = 'Result', }, [0x0051] = { [0x02] = 'Result', }, [0x006C] = { [0x02] = 'Result', [0x10] = 'Info', }, [0x00A2] = { [0x02] = 'Result', }, [0x5558] = { [0x02] = 'Result', [0x01] = 'Profile Identifier', }, }

wds_indications = { [0x0001] = "Event Report", [0x0022] = "Packet Service Status", }

tlv_wds_ind = { [0x0001] = { [0x10] = 'Tx Packets Ok', [0x11] = 'Rx Packets Ok', [0x12] = 'Tx Packets Error', [0x13] = 'Rx Packets Error', [0x14] = 'Tx Overflows', [0x15] = 'Rx Overflows', [0x16] = 'Channel Rates', [0x17] = 'Data Bearer Technology', [0x18] = 'Dormancy Status', [0x19] = 'Tx Bytes Ok', [0x1A] = 'Rx Bytes Ok', [0x1B] = 'MIP Status', [0x1D] = 'Current Data Bearer Technology', [0x1F] = 'Data Call Status', [0x20] = 'Preferred Data System', [0x22] = 'Data Call Type', [0x23] = 'EVDO Page Monitor Period Change', [0x24] = 'Data Systems', [0x25] = 'Tx Packets Dropped', [0x26] = 'Rx Packets Dropped', [0x27] = 'Uplink Flow Control Enabled', [0x28] = 'Data Call Address Family', [0x29] = 'PDN Filters Removed', [0x2A] = 'Extended Data Bearer Technology', }, [0x0022] = { [0x01] = 'Connection Status', [0x10] = 'Call End Reason', [0x11] = 'Verbose Call End Reason', [0x12] = 'IP Family', [0x34] = 'Extended Technology Preference', }, }

wda_messages  = { [0x001E] = "Get Supported Messages", [0x0020] = "Set Data Format", [0x0021] = "Get Data Format",  [0x002B] = "Set QMAP Settings"}

f.msgid_wda = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, wda_messages)

tlv_wda_req = { [0x001E] = { }, [0x0020] = { [0x10] = 'QoS Format', [0x11] = 'Link Layer Protocol', [0x12] = 'Uplink Data Aggregation Protocol', [0x13] = 'Downlink Data Aggregation Protocol', [0x14] = 'NDP Signature', [0x15] = 'Downlink Data Aggregation Max Datagrams', [0x16] = 'Downlink Data Aggregation Max Size', [0x17] = 'Endpoint Info', }, [0x0021] = { }, [0x002B] = { [0x10] = 'QMAP In-Band Flow Control', }, }

tlv_wda_resp = { [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x0020] = { [0x02] = 'Result', [0x10] = 'QoS Format', [0x11] = 'Link Layer Protocol', [0x12] = 'Uplink Data Aggregation Protocol', [0x13] = 'Downlink Data Aggregation Protocol', [0x14] = 'NDP Signature', [0x15] = 'Downlink Data Aggregation Max Datagrams', [0x16] = 'Downlink Data Aggregation Max Size', }, [0x0021] = { [0x02] = 'Result', [0x10] = 'QoS Format', [0x11] = 'Link Layer Protocol', [0x12] = 'Uplink Data Aggregation Protocol', [0x13] = 'Downlink Data Aggregation Protocol', [0x14] = 'NDP Signature', [0x15] = 'Uplink Data Aggregation Max Size', [0x16] = 'Downlink Data Aggregation Max Size', }, [0x002B] = { [0x02] = 'Result',  [0x10] = 'QMAP In-Band Flow Control', }, }

wda_indications = { }

tlv_wda_ind = { }

voice_messages  = { [0x001E] = "Get Supported Messages", [0x0020] = "Dial Call", [0x0021] = "End Call", [0x0022] = "Answer Call", [0x0041] = "Get Config",  }

f.msgid_voice = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, voice_messages)

tlv_voice_req = { [0x001E] = { }, [0x0020] = { [0x01] = 'Calling Number', }, [0x0021] = { [0x01] = 'Call ID', }, [0x0022] = { [0x01] = 'Call ID', }, [0x0041] = { [0x10] = 'Auto Answer', [0x11] = 'Air Timer', [0x12] = 'Roam Timer', [0x13] = 'TTY Mode', [0x14] = 'Preferred Voice Service Option', [0x15] = 'AMR Status', [0x16] = 'Preferred Voice Privacy', [0x17] = 'NAM Index', [0x18] = 'Voice Domain Preference', }, }

tlv_voice_resp = { [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x0020] = { [0x02] = 'Result', [0x10] = 'Call ID', }, [0x0021] = { [0x02] = 'Result', [0x10] = 'Call ID', }, [0x0022] = { [0x02] = 'Result', [0x10] = 'Call ID', }, [0x0041] = { [0x02] = 'Result', [0x10] = 'Auto Answer Status', [0x11] = 'Air Timer Count', [0x12] = 'Roam Timer Count', [0x13] = 'Current TTY Mode', [0x14] = 'Current Preferred Voice SO', [0x15] = 'Current AMR Status', [0x16] = 'Current Voice Privacy Preference', [0x17] = 'Current Voice Domain Preference', }, }

voice_indications = { [0x002E] = "All Call Status", }

tlv_voice_ind = { [0x002E] = { [0x01] = 'Call Information', [0x10] = 'Remote Party Number', }, }

pds_messages  = { [0x0000] = "Reset", [0x0001] = "Set Event Report", [0x0020] = "Get GPS Service State", [0x0021] = "Set GPS Service State", [0x0029] = "Get Default Tracking Session", [0x002A] = "Set Default Tracking Session", [0x002E] = "Get AGPS Config", [0x002F] = "Set AGPS Config", [0x0030] = "Get Auto Tracking State", [0x0031] = "Set Auto Tracking State",  }

f.msgid_pds = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, pds_messages)

tlv_pds_req = { [0x0000] = { }, [0x0001] = { [0x10] = 'NMEA Position Reporting', [0x11] = 'Extended NMEA Position Reporting', [0x12] = 'Parsed Position Reporting', [0x13] = 'External XTRA Data Request Reporting', [0x14] = 'External Time Injection Request Reporting', [0x15] = 'External WIFI Position Request Reporting', [0x16] = 'Satellite Information Reporting', [0x17] = 'VX Network Initiated Request Reporting', [0x18] = 'SUPL Network Initiated Prompt Reporting', [0x19] = 'UMTS CP Network Initiated Prompt Reporting', [0x1A] = 'PDS Comm Event Reporting', [0x1B] = 'Accelerometer Data Streaming Ready Reporting', [0x1C] = 'Gyro Data Streaming Ready Reporting', [0x1D] = 'Time Sync Request Reporting', [0x1E] = 'Position Reliability Indicator Reporting', [0x1F] = 'Sensor Data Usage Indicator Reporting', [0x20] = 'Time Source Information Reporting', [0x21] = 'Heading Uncertainty Reporting', [0x22] = 'NMEA Debug Strings Reporting', [0x23] = 'Extended External XTRA Data Request Reporting', }, [0x0020] = { }, [0x0021] = { [0x01] = 'State', }, [0x0029] = { }, [0x002A] = { [0x01] = 'Info', }, [0x002E] = { [0x12] = 'Network Mode', }, [0x002F] = { [0x10] = 'Location Server Address', [0x11] = 'Location Server URL', [0x14] = 'Network Mode', }, [0x0030] = { }, [0x0031] = { [0x01] = 'State', }, }

tlv_pds_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0001] = { [0x02] = 'Result', }, [0x0020] = { [0x02] = 'Result', [0x01] = 'State', }, [0x0021] = { [0x02] = 'Result', }, [0x0029] = { [0x02] = 'Result', [0x01] = 'Info', }, [0x002A] = { [0x02] = 'Result', }, [0x002E] = { [0x02] = 'Result', [0x10] = 'Location Server Address', [0x11] = 'Location Server URL', }, [0x002F] = { [0x02] = 'Result', }, [0x0030] = { [0x02] = 'Result', [0x01] = 'State', }, [0x0031] = { [0x02] = 'Result', }, }

pds_indications = { [0x0001] = "Event Report", [0x0060] = "GPS Ready", }

tlv_pds_ind = { [0x0001] = { [0x10] = 'NMEA Position', [0x11] = 'Extended NMEA Position', [0x12] = 'Position Session Status', }, [0x0060] = { }, }

nas_messages  = { [0x0000] = "Reset", [0x0001] = "Abort", [0x0002] = "Set Event Report", [0x0003] = "Register Indications", [0x001E] = "Get Supported Messages", [0x0020] = "Get Signal Strength", [0x0021] = "Network Scan", [0x0022] = "Initiate Network Register", [0x0023] = "Attach Detach", [0x0024] = "Get Serving System", [0x0025] = "Get Home Network", [0x002A] = "Set Technology Preference", [0x002B] = "Get Technology Preference", [0x0031] = "Get RF Band Information", [0x0033] = "Set System Selection Preference", [0x0034] = "Get System Selection Preference", [0x0039] = "Get Operator Name", [0x0043] = "Get Cell Location Info", [0x004D] = "Get System Info", [0x004F] = "Get Signal Info", [0x0050] = "Config Signal Info", [0x005A] = "Get Tx Rx Info", [0x0067] = "Force Network Search", [0x0065] = "Get CDMA Position Info", [0x00AC] = "Get LTE Cphy CA Info",  }

f.msgid_nas = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, nas_messages)

tlv_nas_req = { [0x0000] = { }, [0x0001] = { [0x01] = 'Transaction ID', }, [0x0002] = { [0x10] = 'Signal Strength Indicator', [0x11] = 'RF Band Information', [0x12] = 'Registration Reject Reason', [0x13] = 'RSSI Indicator', [0x14] = 'ECIO Indicator', [0x15] = 'IO Indicator', [0x16] = 'SINR Indicator', [0x17] = 'Error Rate Indicator', [0x19] = 'ECIO Threshold', [0x1A] = 'SINR Threshold', [0x1B] = 'LTE SNR Delta', [0x1C] = 'LTE RSRP Delta', }, [0x0003] = { [0x10] = 'System Selection Preference', [0x12] = 'DDTM Events', [0x13] = 'Serving System Events', [0x14] = 'Dual Standby Preference', [0x15] = 'Subscription Info', [0x17] = 'Network Time', [0x18] = 'System Info', [0x19] = 'Signal Info', [0x1A] = 'Error Rate', [0x1B] = 'HDR New UATI Assigned', [0x1C] = 'HDR Session Closed', [0x1D] = 'Managed Roaming', [0x1E] = 'Current PLMN Name', [0x1F] = 'eMBMS Status', [0x20] = 'RF Band Information', }, [0x001E] = { }, [0x0020] = { [0x10] = 'Request Mask', }, [0x0021] = { [0x10] = 'Network Type', }, [0x0022] = { [0x01] = 'Action', [0x10] = 'Manual Registration Info 3GPP', [0x11] = 'Change Duration', [0x12] = 'MNC PCS Digit Include Status', }, [0x0023] = { [0x10] = 'Action', }, [0x0024] = { }, [0x0025] = { }, [0x002A] = { [0x01] = 'Current', }, [0x002B] = { }, [0x0031] = { }, [0x0033] = { [0x10] = 'Emergency mode', [0x11] = 'Mode Preference', [0x12] = 'Band Preference', [0x13] = 'CDMA PRL Preference', [0x14] = 'Roaming Preference', [0x15] = 'LTE Band Preference', [0x16] = 'Network Selection Preference', [0x17] = 'Change Duration', [0x18] = 'Service Domain Preference', [0x19] = 'GSM WCDMA Acquisition Order Preference', [0x1A] = 'MNC PDS Digit Include Status', [0x1D] = 'TD SCDMA Band Preference', [0x1E] = 'Acquisition Order Preference', [0x24] = 'Extended LTE Band Preference', }, [0x0034] = { }, [0x0039] = { }, [0x0043] = { }, [0x004D] = { }, [0x004F] = { }, [0x0050] = { [0x10] = 'RSSI Threshold', [0x11] = 'ECIO Threshold', [0x12] = 'SINR Threshold', [0x13] = 'LTE SNR Threshold', [0x14] = 'IO Threshold', [0x15] = 'RSRQ Threshold', [0x16] = 'RSRP Threshold', [0x17] = 'LTE Report', [0x18] = 'RSCP Threshold', }, [0x005A] = { [0x01] = 'Radio Interface', }, [0x0067] = { }, [0x0065] = { }, [0x00AC] = { }, }

tlv_nas_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0001] = { [0x02] = 'Result', }, [0x0002] = { [0x02] = 'Result', }, [0x0003] = { [0x02] = 'Result', }, [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x0020] = { [0x02] = 'Result', [0x01] = 'Signal Strength', [0x10] = 'Strength List', [0x11] = 'RSSI List', [0x12] = 'ECIO List', [0x13] = 'IO', [0x14] = 'SINR', [0x15] = 'Error Rate List', [0x16] = 'RSRQ', [0x17] = 'LTE SNR', [0x18] = 'LTE RSRP', }, [0x0021] = { [0x02] = 'Result', [0x10] = 'Network Information', [0x11] = 'Radio Access Technology', [0x12] = 'MNC PCS Digit Include Status', }, [0x0022] = { [0x02] = 'Result', }, [0x0023] = { [0x02] = 'Result', }, [0x0024] = { [0x02] = 'Result', [0x01] = 'Serving System', [0x10] = 'Roaming Indicator', [0x11] = 'Data Service Capability', [0x12] = 'Current PLMN', [0x13] = 'CDMA System ID', [0x14] = 'CDMA Base Station Info', [0x15] = 'Roaming Indicator List', [0x16] = 'Default Roaming Indicator', [0x17] = 'Time Zone 3GPP2', [0x18] = 'CDMA P Rev', [0x1A] = 'Time Zone 3GPP', [0x1B] = 'Daylight Saving Time Adjustment 3GPP', [0x1C] = 'LAC 3GPP', [0x1D] = 'CID 3GPP', [0x1E] = 'Concurrent Service Info 3GPP2', [0x1F] = 'PRL Indicator 3GPP2', [0x20] = 'DTM Support', [0x21] = 'Detailed Service Status', [0x22] = 'CDMA System Info', [0x23] = 'HDR Personality', [0x24] = 'LTE TAC', [0x25] = 'Call Barring Status', [0x26] = 'UMTS Primary Scrambling Code', [0x27] = 'MNC PCS Digit Include Status', }, [0x0025] = { [0x02] = 'Result', [0x01] = 'Home Network', [0x10] = 'Home System ID', [0x11] = 'Home Network 3GPP2', [0x12] = 'Home Network 3GPP MNC', }, [0x002A] = { [0x02] = 'Result', }, [0x002B] = { [0x02] = 'Result', [0x01] = 'Active', [0x10] = 'Persistent', }, [0x0031] = { [0x02] = 'Result', [0x01] = 'List', }, [0x0033] = { [0x02] = 'Result', }, [0x0034] = { [0x02] = 'Result', [0x10] = 'Emergency mode', [0x11] = 'Mode Preference', [0x12] = 'Band Preference', [0x13] = 'CDMA PRL Preference', [0x14] = 'Roaming Preference', [0x15] = 'LTE Band Preference', [0x16] = 'Network Selection Preference', [0x18] = 'Service Domain Preference', [0x19] = 'GSM WCDMA Acquisition Order Preference', [0x1A] = 'TD SCDMA Band Preference', [0x1C] = 'Acquisition Order Preference', [0x1B] = 'Manual Network Selection', [0x23] = 'Extended LTE Band Preference', }, [0x0039] = { [0x02] = 'Result', [0x10] = 'Service Provider Name', [0x11] = 'Operator PLMN List', [0x12] = 'Operator PLMN Name', [0x13] = 'Operator String Name', [0x14] = 'Operator NITZ Information', }, [0x0043] = { [0x02] = 'Result', [0x10] = 'GERAN Info', [0x11] = 'UMTS Info', [0x12] = 'CDMA Info', [0x13] = 'Intrafrequency LTE Info', [0x14] = 'Interfrequency LTE Info', [0x15] = 'LTE Info Neighboring GSM', [0x16] = 'LTE Info Neighboring WCDMA', [0x17] = 'UMTS Cell ID', [0x18] = 'UMTS Info Neighboring LTE', }, [0x004D] = { [0x02] = 'Result', [0x10] = 'CDMA Service Status', [0x11] = 'HDR Service Status', [0x12] = 'GSM Service Status', [0x13] = 'WCDMA Service Status', [0x14] = 'LTE Service Status', [0x15] = 'CDMA System Info', [0x16] = 'HDR System Info', [0x17] = 'GSM System Info', [0x18] = 'WCDMA System Info', [0x19] = 'LTE System Info', [0x1A] = 'Additional CDMA System Info', [0x1B] = 'Additional HDR System Info', [0x1C] = 'Additional GSM System Info', [0x1D] = 'Additional WCDMA System Info', [0x1E] = 'Additional LTE System Info', [0x1F] = 'GSM Call Barring Status', [0x20] = 'WCDMA Call Barring Status', [0x21] = 'LTE Voice Support', [0x22] = 'GSM Cipher Domain', [0x23] = 'WCDMA Cipher Domain', [0x24] = 'TD SCDMA Service Status', [0x25] = 'TD SCDMA System Info', [0x26] = 'LTE eMBMS Coverage Info Support', [0x27] = 'SIM Reject Info', }, [0x004F] = { [0x02] = 'Result', [0x10] = 'CDMA Signal Strength', [0x11] = 'HDR Signal Strength', [0x12] = 'GSM Signal Strength', [0x13] = 'WCDMA Signal Strength', [0x14] = 'LTE Signal Strength', [0x15] = 'TDMA Signal Strength', }, [0x0050] = { [0x02] = 'Result', }, [0x005A] = { [0x02] = 'Result', [0x10] = 'Rx Chain 0 Info', [0x11] = 'Rx Chain 1 Info', [0x12] = 'Tx Info', }, [0x0067] = { [0x02] = 'Result', }, [0x0065] = { [0x02] = 'Result', [0x10] = 'CDMA Position Info', }, [0x00AC] = { [0x02] = 'Result', [0x11] = 'DL Bandwidth', [0x12] = 'Phy CA Agg SCell Info', [0x13] = 'Phy CA Agg PCell Info', [0x14] = 'SCell index', [0x15] = 'Phy CA Agg Secondary Cells', }, }

nas_indications = { [0x0002] = "Event Report", [0x0024] = "Serving System", [0x003A] = "Operator Name", [0x004C] = "Network Time", [0x004E] = "System Info", [0x0051] = "Signal Info", }

tlv_nas_ind = { [0x0002] = { [0x10] = 'Signal Strength', [0x11] = 'RF Band Information', [0x12] = 'Registration Reject Reason', [0x13] = 'RSSI', [0x14] = 'ECIO', [0x15] = 'IO', [0x16] = 'SINR', [0x17] = 'Error Rate', [0x18] = 'RSRQ', [0x19] = 'LTE SNR', [0x1A] = 'LTE RSRP', }, [0x0024] = { [0x01] = 'Serving System', [0x10] = 'Roaming Indicator', [0x11] = 'Data Service Capability', [0x12] = 'Current PLMN', [0x13] = 'CDMA System ID', [0x14] = 'CDMA Base Station Info', [0x15] = 'Roaming Indicator List', [0x16] = 'Default Roaming Indicator', [0x17] = 'Time Zone 3GPP2', [0x18] = 'CDMA P Rev', [0x19] = 'PLMN Name Flag 3GPP', [0x1A] = 'Time Zone 3GPP', [0x1B] = 'Daylight Saving Time Adjustment 3GPP', [0x1C] = 'Universal Time and Local Time Zone 3GPP', [0x1D] = 'LAC 3GPP', [0x1E] = 'CID 3GPP', [0x1F] = 'Concurrent Service Info 3GPP2', [0x20] = 'PRL Indicator 3GPP2', [0x21] = 'DTM Support', [0x22] = 'Detailed Service Status', [0x23] = 'CDMA System Info', [0x24] = 'HDR Personality', [0x25] = 'LTE TAC', [0x26] = 'Call Barring Status', [0x27] = 'PLMN Not Changed Indication', [0x28] = 'UMTS Primary Scrambling Code', [0x29] = 'MNC PCS Digit Include Status', }, [0x003A] = { [0x10] = 'Service Provider Name', [0x11] = 'Operator PLMN List', [0x12] = 'Operator PLMN Name', [0x13] = 'Operator String Name', [0x14] = 'Operator NITZ Information', }, [0x004C] = { [0x01] = 'Universal Time', [0x10] = 'Timezone Offset', [0x11] = 'Daylight Savings Adjustment', [0x12] = 'Radio Interface', }, [0x004E] = { [0x10] = 'CDMA Service Status', [0x11] = 'HDR Service Status', [0x12] = 'GSM Service Status', [0x13] = 'WCDMA Service Status', [0x14] = 'LTE Service Status', [0x15] = 'CDMA System Info', [0x16] = 'HDR System Info', [0x17] = 'GSM System Info', [0x18] = 'WCDMA System Info', [0x19] = 'LTE System Info', [0x1A] = 'Additional CDMA System Info', [0x1B] = 'Additional HDR System Info', [0x1C] = 'Additional GSM System Info', [0x1D] = 'Additional WCDMA System Info', [0x1E] = 'Additional LTE System Info', [0x1F] = 'GSM Call Barring Status', [0x20] = 'WCDMA Call Barring Status', [0x21] = 'LTE Voice Support', [0x22] = 'GSM Cipher Domain', [0x23] = 'WCDMA Cipher Domain', [0x24] = 'PLMN Not Changed Indication', [0x25] = 'TD SCDMA Service Status', [0x26] = 'TD SCMA System Info', [0x27] = 'LTE eMBMS Coverage Info Support', [0x28] = 'SIM Reject Info', }, [0x0051] = { [0x10] = 'CDMA Signal Strength', [0x11] = 'HDR Signal Strength', [0x12] = 'GSM Signal Strength', [0x13] = 'WCDMA Signal Strength', [0x14] = 'LTE Signal Strength', [0x15] = 'TDMA Signal Strength', }, }

pdc_messages  = { [0x0000] = "Reset", [0x0001] = "Set Event Report", [0x0020] = "Start Session", [0x0021] = "Cancel Session", [0x0022] = "Get Session Info", [0x0023] = "Send Selection", [0x0024] = "Get Feature Setting", [0x0025] = "Set Feature Setting",  }

f.msgid_pdc = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, pdc_messages)

tlv_pdc_req = { [0x0000] = { }, [0x0001] = { [0x10] = 'Network Initiated Alert Reporting', [0x11] = 'Session State Reporting', }, [0x0020] = { [0x10] = 'Session Type', }, [0x0021] = { }, [0x0022] = { }, [0x0023] = { [0x10] = 'Network Initiated Alert Selection', }, [0x0024] = { }, [0x0025] = { [0x10] = 'Device Provisioning Service Update Config', [0x11] = 'PRL Update Service Config', [0x12] = 'HFA Feature Config', }, }

tlv_pdc_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0001] = { [0x02] = 'Result', }, [0x0020] = { [0x02] = 'Result', }, [0x0021] = { [0x02] = 'Result', }, [0x0022] = { [0x10] = 'Session Info', [0x11] = 'Session Failed Reason', [0x12] = 'Retry Info', [0x13] = 'Network Initiated Alert', [0x02] = 'Result', }, [0x0023] = { [0x02] = 'Result', }, [0x0024] = { [0x10] = 'Device Provisioning Service Update Config', [0x11] = 'PRL Update Service Config', [0x12] = 'HFA Feature Config', [0x13] = 'HFA Feature Done State', [0x02] = 'Result', }, [0x0025] = { [0x02] = 'Result', }, }

pdc_indications = { [0x0001] = "Event Report", }

tlv_pdc_ind = { [0x0001] = { [0x10] = 'Network Initiated Alert', [0x11] = 'Session State', [0x12] = 'Session Fail Reason', }, }

pdc_messages  = { [0x0000] = "Reset", [0x20] = "Register", [0x21] = "Config Change", [0x22] = "Get Selected Config", [0x23] = "Set Selected Config", [0x24] = "List Configs", [0x25] = "Delete Config", [0x26] = "Load Config", [0x27] = "Activate Config", [0x28] = "Get Config Info", [0x29] = "Get Config Limits", [0x2A] = "Get Default Config Info", [0x2B] = "Deactivate Config",  }

f.msgid_pdc = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, pdc_messages)

tlv_pdc_req = { [0x0000] = { }, [0x20] = { [0x10] = 'Enable Reporting', }, [0x21] = { }, [0x22] = { }, [0x23] = { }, [0x24] = { [0x11] = 'Config Type', }, [0x25] = { [0x11] = 'Id', }, [0x26] = { [0x1] = 'Config Chunk', }, [0x27] = { }, [0x28] = { }, [0x29] = { }, [0x2A] = { }, [0x2B] = { }, }

tlv_pdc_resp = { [0x0000] = { [0x02] = 'Result', }, [0x20] = { [0x02] = 'Result', }, [0x21] = { [0x02] = 'Result', }, [0x22] = { [0x02] = 'Result', }, [0x23] = { [0x02] = 'Result', }, [0x24] = { [0x02] = 'Result', }, [0x25] = { [0x02] = 'Result', }, [0x26] = { [0x02] = 'Result', }, [0x27] = { [0x02] = 'Result', }, [0x28] = { [0x02] = 'Result', }, [0x29] = { [0x02] = 'Result', [0x11] = 'Maximum Size', [0x12] = 'Current Size', }, [0x2A] = { [0x02] = 'Result', [0x11] = 'Version', [0x12] = 'Total Size', [0x13] = 'Description', }, [0x2B] = { [0x02] = 'Result', }, }

pdc_indications = { [0x22] = "Get Selected Config", [0x23] = "Set Selected Config", [0x24] = "List Configs", [0x26] = "Load Config", [0x27] = "Activate Config", [0x28] = "Get Config Info", [0x2B] = "Deactivate Config", }

tlv_pdc_ind = { [0x22] = { [0x11] = 'Active Id', [0x12] = 'Pending Id', }, [0x23] = { }, [0x24] = { [0x11] = 'Configs', }, [0x26] = { [0x11] = 'Received', [0x12] = 'Remaining Size', [0x13] = 'Frame Reset', }, [0x27] = { }, [0x28] = { [0x11] = 'Total Size', [0x12] = 'Description', [0x13] = 'Version', }, [0x2B] = { }, }

loc_messages  = { [0x0021] = "Register Events", [0x0022] = "Start", [0x0023] = "Stop", [0x0035] = "Inject Predicted Orbits Data", [0x0036] = "Get Predicted Orbits Data Source", [0x0042] = "Set Server", [0x0043] = "Get Server", [0x0044] = "Delete Assistance Data", [0x004A] = "Set Operation Mode", [0x004B] = "Get Operation Mode", [0x00A7] = "Inject Xtra Data",  }

f.msgid_loc = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, loc_messages)

tlv_loc_req = { [0x0021] = { [0x01] = 'Event Registration Mask', }, [0x0022] = { [0x01] = 'Session ID', [0x12] = 'Intermediate Report State', [0x13] = 'Minimum Interval between Position Reports', }, [0x0023] = { [0x01] = 'Session ID', }, [0x0035] = { [0x01] = 'Total Size', [0x02] = 'Total Parts', [0x03] = 'Part Number', [0x04] = 'Part Data', [0x10] = 'Format Type', }, [0x0036] = { }, [0x0042] = { [0x01] = 'Server Type', }, [0x0043] = { [0x01] = 'Server Type', [0x10] = 'Server Address Type', }, [0x0044] = { [0x01] = 'Delete All', [0x10] = 'Delete SV Info', [0x11] = 'Delete GNSS Data Mask', [0x12] = 'Delete Cell Database Mask', [0x13] = 'Delete Clock Info Mask', }, [0x004A] = { [0x01] = 'Operation Mode', }, [0x004B] = { }, [0x00A7] = { [0x01] = 'Total Size', [0x02] = 'Total Parts', [0x03] = 'Part Number', [0x04] = 'Part Data', }, }

tlv_loc_resp = { [0x0021] = { [0x02] = 'Result', }, [0x0022] = { [0x02] = 'Result', }, [0x0023] = { [0x02] = 'Result', }, [0x0035] = { [0x02] = 'Result', }, [0x0036] = { [0x02] = 'Result', }, [0x0042] = { [0x02] = 'Result', }, [0x0043] = { [0x02] = 'Result', }, [0x0044] = { [0x02] = 'Result', }, [0x004A] = { [0x02] = 'Result', }, [0x004B] = { [0x02] = 'Result', }, [0x00A7] = { [0x02] = 'Result', }, }

loc_indications = { [0x0024] = "Position Report", [0x0026] = "NMEA", [0x002B] = "Engine State", [0x002C] = "Fix Recurrence Type", [0x0025] = "GNSS Sv Info", [0x0035] = "Inject Predicted Orbits Data", [0x0036] = "Get Predicted Orbits Data Source", [0x0042] = "Set Server", [0x0043] = "Get Server", [0x0044] = "Delete Assistance Data", [0x004A] = "Set Operation Mode", [0x004B] = "Get Operation Mode", [0x00A7] = "Inject Xtra Data", }

tlv_loc_ind = { [0x0024] = { [0x01] = 'Session Status', [0x02] = 'Session ID', [0x10] = 'Latitude', [0x11] = 'Longitude', [0x12] = 'Horizontal Uncertainty Circular', [0x13] = 'Horizontal Uncertainty Elliptical Minor', [0x14] = 'Horizontal Uncertainty Elliptical Major', [0x15] = 'Horizontal Uncertainty Elliptical Azimuth', [0x16] = 'Horizontal Confidence', [0x17] = 'Horizontal Reliability', [0x18] = 'Horizontal Speed', [0x19] = 'Speed Uncertainty', [0x1A] = 'Altitude from Ellipsoid', [0x1B] = 'Altitude from Sealevel', [0x1C] = 'Vertical Uncertainty', [0x1D] = 'Vertical Confidence', [0x1E] = 'Vertical Reliability', [0x1F] = 'Vertical Speed', [0x20] = 'Heading', [0x21] = 'Heading Uncertainty', [0x22] = 'Magnetic Deviation', [0x23] = 'Technology Used', [0x24] = 'Dilution of Precision', [0x25] = 'UTC Timestamp', [0x26] = 'Leap Seconds', [0x27] = 'GPS Time', [0x28] = 'Time Uncertainty', [0x29] = 'Time Source', [0x2A] = 'Sensor Data Usage', [0x2B] = 'Session Fix Count', [0x2C] = 'Satellites Used', [0x2D] = 'Altitude Assumed', }, [0x0026] = { [0x01] = 'NMEA String', }, [0x002B] = { [0x01] = 'Engine State', }, [0x002C] = { }, [0x0025] = { [0x01] = 'Altitude Assumed', [0x10] = 'List', }, [0x0035] = { [0x10] = 'Part Number', }, [0x0036] = { [0x10] = 'Allowed Sizes', [0x11] = 'Server List', }, [0x0042] = { }, [0x0043] = { [0x02] = 'Server Type', }, [0x0044] = { }, [0x004A] = { }, [0x004B] = { [0x10] = 'Operation Mode', }, [0x00A7] = { [0x10] = 'Part Number', }, }

uim_messages  = { [0x0000] = "Reset", [0x001E] = "Get Supported Messages", [0x0020] = "Read Transparent", [0x0021] = "Read Record", [0x0024] = "Get File Attributes", [0x0025] = "Set PIN Protection", [0x0026] = "Verify PIN", [0x0027] = "Unblock PIN", [0x0028] = "Change PIN", [0x002F] = "Get Card Status", [0x0030] = "Power Off SIM", [0x0031] = "Power On SIM",  }

f.msgid_uim = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, uim_messages)

tlv_uim_req = { [0x0000] = { }, [0x001E] = { }, [0x0020] = { [0x02] = 'File', [0x03] = 'Read Information', [0x10] = 'Response In Indication Token', [0x11] = 'Encrypt Data', }, [0x0021] = { [0x02] = 'File', [0x03] = 'Record', [0x10] = 'Last Record', [0x11] = 'Response In Indication Token', }, [0x0024] = { [0x02] = 'File', [0x10] = 'Response In Indication Token', }, [0x0025] = { [0x02] = 'Info', [0x11] = 'Response In Indication Token', }, [0x0026] = { [0x02] = 'Info', [0x12] = 'Response In Indication Token', }, [0x0027] = { [0x02] = 'Info', [0x11] = 'Response In Indication Token', }, [0x0028] = { [0x02] = 'Info', [0x11] = 'Response In Indication Token', }, [0x002F] = { }, [0x0030] = { [0x01] = 'Slot', }, [0x0031] = { [0x01] = 'Slot', }, }

tlv_uim_resp = { [0x0000] = { [0x02] = 'Result', }, [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x0020] = { [0x02] = 'Result', [0x10] = 'Card result', [0x11] = 'Read result', [0x12] = 'Response In Indication Token', [0x13] = 'Encrypted Data', }, [0x0021] = { [0x02] = 'Result', [0x10] = 'Card result', [0x11] = 'Read Result', [0x12] = 'Additional Read Result', [0x13] = 'Response In Indication Token', }, [0x0024] = { [0x02] = 'Result', [0x10] = 'Card result', [0x11] = 'File Attributes', [0x12] = 'Response In Indication Token', }, [0x0025] = { [0x02] = 'Result', [0x10] = 'Retries Remaining', [0x12] = 'Response In Indication Token', }, [0x0026] = { [0x02] = 'Result', [0x10] = 'Retries Remaining', [0x12] = 'Response In Indication Token', [0x13] = 'Card Result', }, [0x0027] = { [0x02] = 'Result', [0x10] = 'Retries Remaining', [0x12] = 'Response In Indication Token', [0x13] = 'Card Result', }, [0x0028] = { [0x02] = 'Result', [0x10] = 'Retries Remaining', [0x12] = 'Response In Indication Token', [0x13] = 'Card Result', }, [0x002F] = { [0x02] = 'Result', }, [0x0030] = { [0x02] = 'Result', }, [0x0031] = { [0x02] = 'Result', }, }

uim_indications = { [0x0032] = "Card Status", }

tlv_uim_ind = { [0x0032] = { }, }

ctl_messages  = { [0x0020] = "Set Instance ID", [0x0021] = "Get Version Info", [0x0022] = "Allocate CID", [0x0023] = "Release CID", [0x0026] = "Set Data Format", [0x0027] = "Sync", [0xFF00] = "Internal Proxy Open",  }

f.msgid_ctl = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, ctl_messages)

tlv_ctl_req = { [0x0020] = { [0x01] = 'ID', }, [0x0021] = { }, [0x0022] = { [0x01] = 'Service', }, [0x0023] = { [0x01] = 'Release Info', }, [0x0026] = { [0x01] = 'Format', [0x10] = 'Protocol', }, [0x0027] = { }, [0xFF00] = { [0x01] = 'Device Path', }, }

tlv_ctl_resp = { [0x0020] = { [0x02] = 'Result', [0x01] = 'Link ID', }, [0x0021] = { [0x02] = 'Result', [0x01] = 'Service list', }, [0x0022] = { [0x02] = 'Result', [0x01] = 'Allocation Info', }, [0x0023] = { [0x02] = 'Result', [0x01] = 'Release Info', }, [0x0026] = { [0x02] = 'Result', [0x10] = 'Protocol', }, [0x0027] = { [0x02] = 'Result', }, [0xFF00] = { [0x02] = 'Result', }, }

ctl_indications = { [0x0027] = "Sync", }

tlv_ctl_ind = { [0x0027] = { }, }

dms_messages  = { [0x0000] = "Reset", [0x0001] = "Set Event Report", [0x0020] = "Get Capabilities", [0x0021] = "Get Manufacturer", [0x0022] = "Get Model", [0x0023] = "Get Revision", [0x0024] = "Get MSISDN", [0x0025] = "Get IDs", [0x0026] = "Get Power State", [0x0027] = "UIM Set PIN Protection", [0x0028] = "UIM Verify PIN", [0x0029] = "UIM Unblock PIN", [0x002A] = "UIM Change PIN", [0x002B] = "UIM Get PIN Status", [0x002C] = "Get Hardware Revision", [0x002D] = "Get Operating Mode", [0x002E] = "Set Operating Mode", [0x002F] = "Get Time", [0x0030] = "Get PRL Version", [0x0031] = "Get Activation State", [0x0032] = "Activate Automatic", [0x0033] = "Activate Manual", [0x0034] = "Get User Lock State", [0x0035] = "Set User Lock State", [0x0036] = "Set User Lock Code", [0x0037] = "Read User Data", [0x0038] = "Write User Data", [0x0039] = "Read ERI File", [0x003A] = "Restore Factory Defaults", [0x003B] = "Validate Service Programming Code", [0x003C] = "UIM Get ICCID", [0x003E] = "Set Firmware ID", [0x0040] = "UIM Get CK Status", [0x0041] = "UIM Set CK Protection", [0x0042] = "UIM Unblock CK", [0x0043] = "UIM Get IMSI", [0x0044] = "UIM Get State", [0x0045] = "Get Band Capabilities", [0x0046] = "Get Factory SKU", [0x0047] = "Get Firmware Preference", [0x0048] = "Set Firmware Preference", [0x0049] = "List Stored Images", [0x004A] = "Delete Stored Image", [0x004B] = "Set Time", [0x004C] = "Get Stored Image Info", [0x004D] = "Get Alt Net Config", [0x004E] = "Set Alt Net Config", [0x004F] = "Get Boot Image Download Mode", [0x0050] = "Set Boot Image Download Mode", [0x0051] = "Get Software Version", [0x0052] = "Set Service Programming Code", [0x001E] = "Get Supported Messages", [0x5556] = "HP Change Device Mode", [0x5556] = "Swi Get Current Firmware", [0x555B] = "Swi Get USB Composition", [0x555C] = "Swi Set USB Composition", [0x555F] = "Set FCC Authentication",  }

f.msgid_dms = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX, dms_messages)

tlv_dms_req = { [0x0000] = { }, [0x0001] = { [0x10] = 'Power State Reporting', [0x11] = 'Battery Level Report Limits', [0x12] = 'PIN State Reporting', [0x13] = 'Activation State Reporting', [0x14] = 'Operating Mode Reporting', [0x15] = 'UIM State Reporting', [0x16] = 'Wireless Disable State Reporting', [0x17] = 'PRL Init Reporting', }, [0x0020] = { }, [0x0021] = { }, [0x0022] = { }, [0x0023] = { }, [0x0024] = { }, [0x0025] = { }, [0x0026] = { }, [0x0027] = { [0x01] = 'Info', }, [0x0028] = { [0x01] = 'Info', }, [0x0029] = { [0x01] = 'Info', }, [0x002A] = { [0x01] = 'Info', }, [0x002B] = { }, [0x002C] = { }, [0x002D] = { }, [0x002E] = { [0x01] = 'Mode', }, [0x002F] = { }, [0x0030] = { }, [0x0031] = { }, [0x0032] = { [0x01] = 'Activation Code', }, [0x0033] = { [0x01] = 'Info', [0x11] = 'MN HA key', [0x12] = 'MN AAA key', [0x13] = 'PRL', }, [0x0034] = { }, [0x0035] = { [0x01] = 'Info', }, [0x0036] = { [0x01] = 'Info', }, [0x0037] = { }, [0x0038] = { [0x01] = 'User Data', }, [0x0039] = { }, [0x003A] = { [0x01] = 'Service Programming Code', }, [0x003B] = { [0x01] = 'Service Programming Code', }, [0x003C] = { }, [0x003E] = { }, [0x0040] = { [0x01] = 'Facility', }, [0x0041] = { [0x01] = 'Facility', }, [0x0042] = { [0x01] = 'Facility', }, [0x0043] = { }, [0x0044] = { }, [0x0045] = { }, [0x0046] = { }, [0x0047] = { }, [0x0048] = { [0x01] = 'List', [0x10] = 'Download Override', [0x11] = 'Modem Storage Index', }, [0x0049] = { }, [0x004A] = { [0x01] = 'Image', }, [0x004B] = { [0x01] = 'Time Value', [0x10] = 'Time Reference Type', }, [0x004C] = { [0x01] = 'Image', }, [0x004D] = { }, [0x004E] = { [0x01] = 'Config', }, [0x004F] = { }, [0x0050] = { [0x01] = 'Mode', }, [0x0051] = { }, [0x0052] = { [0x01] = 'Current Code', [0x02] = 'New Code', }, [0x001E] = { }, [0x5556] = { [0x01] = 'Mode', }, [0x5556] = { }, [0x555B] = { }, [0x555C] = { [0x01] = 'Current', }, [0x555F] = { }, }

tlv_dms_resp = { [0x0000] = { [0x02] = 'Result', }, [0x0001] = { [0x02] = 'Result', }, [0x0020] = { [0x02] = 'Result', [0x01] = 'Info', }, [0x0021] = { [0x02] = 'Result', [0x01] = 'Manufacturer', }, [0x0022] = { [0x02] = 'Result', [0x01] = 'Model', }, [0x0023] = { [0x02] = 'Result', [0x01] = 'Revision', }, [0x0024] = { [0x02] = 'Result', [0x01] = 'MSISDN', }, [0x0025] = { [0x02] = 'Result', [0x10] = 'Esn', [0x11] = 'Imei', [0x12] = 'Meid', }, [0x0026] = { [0x02] = 'Result', [0x01] = 'Info', }, [0x0027] = { [0x02] = 'Result', [0x10] = 'Pin Retries Status', }, [0x0028] = { [0x02] = 'Result', [0x10] = 'Pin Retries Status', }, [0x0029] = { [0x02] = 'Result', [0x10] = 'Pin Retries Status', }, [0x002A] = { [0x02] = 'Result', [0x10] = 'Pin Retries Status', }, [0x002B] = { [0x02] = 'Result', [0x11] = 'PIN1 Status', [0x12] = 'PIN2 Status', }, [0x002C] = { [0x02] = 'Result', [0x01] = 'Revision', }, [0x002D] = { [0x02] = 'Result', [0x01] = 'Mode', [0x10] = 'Offline Reason', [0x11] = 'Hardware Restricted Mode', }, [0x002E] = { [0x02] = 'Result', }, [0x002F] = { [0x02] = 'Result', [0x01] = 'Device Time', [0x10] = 'System Time', [0x11] = 'User Time', }, [0x0030] = { [0x02] = 'Result', [0x01] = 'Version', [0x10] = 'PRL Only Preference', }, [0x0031] = { [0x02] = 'Result', [0x01] = 'Info', }, [0x0032] = { [0x02] = 'Result', }, [0x0033] = { [0x02] = 'Result', }, [0x0034] = { [0x02] = 'Result', [0x01] = 'Enabled', }, [0x0035] = { [0x02] = 'Result', }, [0x0036] = { [0x02] = 'Result', }, [0x0037] = { [0x02] = 'Result', [0x01] = 'User Data', }, [0x0038] = { [0x02] = 'Result', }, [0x0039] = { [0x02] = 'Result', [0x01] = 'ERI File', }, [0x003A] = { [0x02] = 'Result', }, [0x003B] = { [0x02] = 'Result', }, [0x003C] = { [0x02] = 'Result', [0x01] = 'ICCID', }, [0x003E] = { [0x02] = 'Result', }, [0x0040] = { [0x02] = 'Result', [0x01] = 'CK Status', [0x10] = 'Operation Blocking Facility', }, [0x0041] = { [0x02] = 'Result', [0x10] = 'Verify Retries Left', }, [0x0042] = { [0x02] = 'Result', [0x10] = 'Unblock Retries Left', }, [0x0043] = { [0x02] = 'Result', [0x01] = 'IMSI', }, [0x0044] = { [0x02] = 'Result', [0x01] = 'State', }, [0x0045] = { [0x02] = 'Result', [0x01] = 'Band Capability', [0x10] = 'LTE Band Capability', [0x12] = 'Extended LTE Band Capability', }, [0x0046] = { [0x02] = 'Result', [0x01] = 'SKU', }, [0x0047] = { [0x02] = 'Result', [0x01] = 'List', }, [0x0048] = { [0x02] = 'Result', [0x01] = 'Image Download List', }, [0x0049] = { [0x02] = 'Result', [0x01] = 'List', }, [0x004A] = { [0x02] = 'Result', }, [0x004B] = { [0x02] = 'Result', }, [0x004C] = { [0x02] = 'Result', [0x10] = 'Boot Version', [0x11] = 'PRI Version', [0x12] = 'OEM Lock ID', }, [0x004D] = { [0x02] = 'Result', [0x01] = 'Config', }, [0x004E] = { [0x02] = 'Result', }, [0x004F] = { [0x02] = 'Result', [0x10] = 'Mode', }, [0x0050] = { [0x02] = 'Result', }, [0x0051] = { [0x02] = 'Result', [0x01] = 'Version', }, [0x0052] = { [0x02] = 'Result', }, [0x001E] = { [0x02] = 'Result', [0x10] = 'List', }, [0x5556] = { [0x02] = 'Result', }, [0x5556] = { [0x02] = 'Result', [0x10] = 'Model', [0x11] = 'Boot version', [0x12] = 'AMSS version', [0x13] = 'SKU ID', [0x14] = 'Package ID', [0x15] = 'Carrier ID', [0x16] = 'PRI version', [0x17] = 'Carrier', [0x18] = 'Config version', }, [0x555B] = { [0x02] = 'Result', [0x10] = 'Current', [0x11] = 'Supported', }, [0x555C] = { [0x02] = 'Result', }, [0x555F] = { [0x02] = 'Result', }, }

dms_indications = { [0x0001] = "Event Report", }

tlv_dms_ind = { [0x0001] = { [0x10] = 'Power State', [0x11] = 'PIN1 Status', [0x12] = 'PIN2 Status', [0x13] = 'Activation State', [0x14] = 'Operating Mode', [0x15] = 'UIM State', [0x16] = 'Wireless Disable State', [0x17] = 'PRL Init Notification', }, }

f.msglen =    ProtoField.uint16("qmi.message_len", "Message Length", base.DEC)
-- TLVs
f.tlvt =      ProtoField.uint8("qmi.tlv_type", "TLV Type", base.HEX)
f.tlvl =      ProtoField.uint16("qmi.tlv_len", "TLV Length", base.DEC)
f.tlvv =      ProtoField.bytes("qmi.tlv_value", "TLV Value")


local usb_transfer_type = Field.new("usb.transfer_type")
local usb_endpoint = Field.new("usb.endpoint_address")

f.qmhdrcd = ProtoField.uint8("qmaphdr.ctl_data", "Control/Data Bit", base.DEC, nil, 0x80)
f.qmhdrpad = ProtoField.uint8("qmaphdr.pad", "Pad Size", base.DEC, nil, 0x3f)
f.qmhdrmuxid = ProtoField.uint8("qmaphdr.muxid", "MUX ID", base.HEX)
f.qmhdrpayload = ProtoField.uint16("qmaphdr.datasize", "Payload Size", base.DEC)
f.qmpl = ProtoField.bytes("qm.payload", "Payload")
f.qmplpad = ProtoField.bytes("qm.plpad", "Pad")

--
-- Dissector Function
--
function qmi_proto.dissector(buffer, pinfo, tree)
	-- Set off according to operating system
	local off
	local transfer_type = usb_transfer_type().value
	local endpoint = usb_endpoint().value
	
	if package.config:sub(1,1) == '\\' then
		-- USB pcap pseudoheader
		if transfer_type == 2 then
			off = 28
		else
			off = 27
		end
	else
		-- URB header size
		off = 64
	end
	
	--print("length: " .. length)
	--print("\ttransfer_type: " .. transfer_type)
	--print("\tendpoint: " .. endpoint)

	if transfer_type == 3 then
		local length = buffer:len() - off
		while length >= 4 do
			local cdbit = bit.band(buffer(off, 1):uint(), 0x80)
			local pad_size = bit.band(buffer(off, 1):uint(), 0x3f)
			local payload_size = buffer(off + 2, 2):uint()
			
			if (payload_size + 4) > length then return end

			local qmtree = tree:add(qmi_proto, buffer(off, 4 + payload_size), "QMAP")
			local qmhdrtree = qmtree:add(qmi_proto, buffer(off, 4), "QMAP Header")
			qmhdrtree:add(f.qmhdrcd, buffer(off, 1))
			qmhdrtree:add(f.qmhdrpad, buffer(off, 1))
			qmhdrtree:add(f.qmhdrmuxid, buffer(off + 1, 1))
			qmhdrtree:add(f.qmhdrpayload, buffer(off + 2, 2))
			if payload_size > 0 then
				qmtree:add(f.qmpl, buffer(off + 4 , payload_size))
			end

			if payload_size > 0 and cdbit == 0 then
				Dissector.get("ip"):call(buffer(off + 4):tvb(), pinfo, tree)
				if pad_size > 0 then
					tree:add(f.qmplpad, buffer(off + 4 + payload_size - pad_size, pad_size))
				end
			end
			off = off + 4 + payload_size
			length = length - 4 - payload_size
		end
		return
	end

	if buffer:len() - off < 12 then
		-- No payload or too short (12 is a min size)
		return
	end

	-- QMUX Header (6 bytes), see GobiNet/QMI.h
	local tf = buffer(off,1)	-- Always 0x01
	if tf:uint() ~= 1 then
		-- Not a QMI packet
		return
	end
	local len = buffer(off+1,2)	-- Length
	if len:le_uint() ~= buffer:len() - off - 1 then
		-- Length does not match
		return
	end
	local flag = buffer(off+3,1)	-- Always 0x00 (out) or 0x80 (in)
	if flag:uint() ~= 0x00 and flag:uint() ~= 0x80 then
		-- Not a QMI packet
		return
	end
	local svcid = buffer(off+4,1)	-- Service ID
	local cid = buffer(off+5,1)	-- Client ID

	-- Setup protocol subtree
	local qmitree = tree:add(qmi_proto, buffer(off, buffer:len() - off), "QMI")
	local hdrtree = qmitree:add(qmi_proto, buffer(off, 6), "QMUX Header")
	hdrtree:add(f.tf, tf)
	hdrtree:add_le(f.len, len)
	hdrtree:add(f.flag, flag)
	hdrtree:add(f.svcid, svcid)
	hdrtree:add(f.cid, cid)
	off = off + 6

	-- Transaction Header (2 or 3 bytes), see GobiAPI/Core/QMIBuffers.h
	local responsebit
	local indicationbit
	if svcid:uint() == 0 then
		responsebit = buffer(off, 1):bitfield(7)
		indicationbit = buffer(off, 1):bitfield(6)
		local thdrtree = qmitree:add(qmi_proto, buffer(off, 2), "Transaction Header")
		tid = buffer(off+1,1)
		thdrtree:add(f.resp_ctl, buffer(off, 1))
		thdrtree:add(f.ind_ctl, buffer(off, 1))
		thdrtree:add(f.tid_ctl, tid)
		off = off + 2
	else
		responsebit = buffer(off, 1):bitfield(6)
		indicationbit = buffer(off, 1):bitfield(5)
		local thdrtree = qmitree:add(qmi_proto, buffer(off, 3), "Transaction Header")
		tid = buffer(off+1,2)
		thdrtree:add(f.comp_svc, buffer(off, 1))
		thdrtree:add(f.resp_svc, buffer(off, 1))
		thdrtree:add(f.ind_svc, buffer(off, 1))
		thdrtree:add_le(f.tid_svc, tid)
		off = off + 3
	end

	-- Message Header (4 bytes), see GobiAPI/Core/QMIBuffers.h
	local msgstr
	msgid = buffer(off, 2)
	msglen = buffer(off+2, 2)
	local mhdrtree = qmitree:add(qmi_proto, buffer(off, 4), "Message Header")
	if svcid:uint() == 16 then
		mhdrtree:add_le(f.msgid_loc, msgid)
		if indicationbit == 1 then
			msgstr = loc_indications[msgid:le_uint()]
			tlv_description = tlv_loc_ind
		elseif responsebit == 1 then
			msgstr = loc_messages[msgid:le_uint()]
			tlv_description = tlv_loc_resp
		else
			msgstr = loc_messages[msgid:le_uint()]
			tlv_description = tlv_loc_req
		end
	elseif svcid:uint() == 9 then
		mhdrtree:add_le(f.msgid_voice, msgid)
		if indicationbit == 1 then
			msgstr = voice_indications[msgid:le_uint()]
			tlv_description = tlv_voice_ind
		elseif responsebit == 1 then
			msgstr = voice_messages[msgid:le_uint()]
			tlv_description = tlv_voice_resp
		else
			msgstr = voice_messages[msgid:le_uint()]
			tlv_description = tlv_voice_req
		end
	elseif svcid:uint() == 4 then
		mhdrtree:add_le(f.msgid_qos, msgid)
		if indicationbit == 1 then
			msgstr = qos_indications[msgid:le_uint()]
			tlv_description = tlv_qos_ind
		elseif responsebit == 1 then
			msgstr = qos_messages[msgid:le_uint()]
			tlv_description = tlv_qos_resp
		else
			msgstr = qos_messages[msgid:le_uint()]
			tlv_description = tlv_qos_req
		end
	elseif svcid:uint() == 26 then
		mhdrtree:add_le(f.msgid_wda, msgid)
		if indicationbit == 1 then
			msgstr = wda_indications[msgid:le_uint()]
			tlv_description = tlv_wda_ind
		elseif responsebit == 1 then
			msgstr = wda_messages[msgid:le_uint()]
			tlv_description = tlv_wda_resp
		else
			msgstr = wda_messages[msgid:le_uint()]
			tlv_description = tlv_wda_req
		end
	elseif svcid:uint() == 5 then
		mhdrtree:add_le(f.msgid_wms, msgid)
		if indicationbit == 1 then
			msgstr = wms_indications[msgid:le_uint()]
			tlv_description = tlv_wms_ind
		elseif responsebit == 1 then
			msgstr = wms_messages[msgid:le_uint()]
			tlv_description = tlv_wms_resp
		else
			msgstr = wms_messages[msgid:le_uint()]
			tlv_description = tlv_wms_req
		end
	elseif svcid:uint() == 11 then
		mhdrtree:add_le(f.msgid_uim, msgid)
		if indicationbit == 1 then
			msgstr = uim_indications[msgid:le_uint()]
			tlv_description = tlv_uim_ind
		elseif responsebit == 1 then
			msgstr = uim_messages[msgid:le_uint()]
			tlv_description = tlv_uim_resp
		else
			msgstr = uim_messages[msgid:le_uint()]
			tlv_description = tlv_uim_req
		end
	elseif svcid:uint() == 6 then
		mhdrtree:add_le(f.msgid_pds, msgid)
		if indicationbit == 1 then
			msgstr = pds_indications[msgid:le_uint()]
			tlv_description = tlv_pds_ind
		elseif responsebit == 1 then
			msgstr = pds_messages[msgid:le_uint()]
			tlv_description = tlv_pds_resp
		else
			msgstr = pds_messages[msgid:le_uint()]
			tlv_description = tlv_pds_req
		end
	elseif svcid:uint() == 14 then
		mhdrtree:add_le(f.msgid_rmtfs, msgid)
		if indicationbit == 1 then
			msgstr = rmtfs_indications[msgid:le_uint()]
			tlv_description = tlv_rmtfs_ind
		elseif responsebit == 1 then
			msgstr = rmtfs_messages[msgid:le_uint()]
			tlv_description = tlv_rmtfs_resp
		else
			msgstr = rmtfs_messages[msgid:le_uint()]
			tlv_description = tlv_rmtfs_req
		end
	elseif svcid:uint() == 7 then
		mhdrtree:add_le(f.msgid_auth, msgid)
		if indicationbit == 1 then
			msgstr = auth_indications[msgid:le_uint()]
			tlv_description = tlv_auth_ind
		elseif responsebit == 1 then
			msgstr = auth_messages[msgid:le_uint()]
			tlv_description = tlv_auth_resp
		else
			msgstr = auth_messages[msgid:le_uint()]
			tlv_description = tlv_auth_req
		end
	elseif svcid:uint() == 3 then
		mhdrtree:add_le(f.msgid_nas, msgid)
		if indicationbit == 1 then
			msgstr = nas_indications[msgid:le_uint()]
			tlv_description = tlv_nas_ind
		elseif responsebit == 1 then
			msgstr = nas_messages[msgid:le_uint()]
			tlv_description = tlv_nas_resp
		else
			msgstr = nas_messages[msgid:le_uint()]
			tlv_description = tlv_nas_req
		end
	elseif svcid:uint() == 10 then
		mhdrtree:add_le(f.msgid_cat2, msgid)
		if indicationbit == 1 then
			msgstr = cat2_indications[msgid:le_uint()]
			tlv_description = tlv_cat2_ind
		elseif responsebit == 1 then
			msgstr = cat2_messages[msgid:le_uint()]
			tlv_description = tlv_cat2_resp
		else
			msgstr = cat2_messages[msgid:le_uint()]
			tlv_description = tlv_cat2_req
		end
	elseif svcid:uint() == 1 then
		mhdrtree:add_le(f.msgid_wds, msgid)
		if indicationbit == 1 then
			msgstr = wds_indications[msgid:le_uint()]
			tlv_description = tlv_wds_ind
		elseif responsebit == 1 then
			msgstr = wds_messages[msgid:le_uint()]
			tlv_description = tlv_wds_resp
		else
			msgstr = wds_messages[msgid:le_uint()]
			tlv_description = tlv_wds_req
		end
	elseif svcid:uint() == 8 then
		mhdrtree:add_le(f.msgid_at, msgid)
		if indicationbit == 1 then
			msgstr = at_indications[msgid:le_uint()]
			tlv_description = tlv_at_ind
		elseif responsebit == 1 then
			msgstr = at_messages[msgid:le_uint()]
			tlv_description = tlv_at_resp
		else
			msgstr = at_messages[msgid:le_uint()]
			tlv_description = tlv_at_req
		end
	elseif svcid:uint() == 17 then
		mhdrtree:add_le(f.msgid_sar, msgid)
		if indicationbit == 1 then
			msgstr = sar_indications[msgid:le_uint()]
			tlv_description = tlv_sar_ind
		elseif responsebit == 1 then
			msgstr = sar_messages[msgid:le_uint()]
			tlv_description = tlv_sar_resp
		else
			msgstr = sar_messages[msgid:le_uint()]
			tlv_description = tlv_sar_req
		end
	elseif svcid:uint() == 0 then
		mhdrtree:add_le(f.msgid_ctl, msgid)
		if indicationbit == 1 then
			msgstr = ctl_indications[msgid:le_uint()]
			tlv_description = tlv_ctl_ind
		elseif responsebit == 1 then
			msgstr = ctl_messages[msgid:le_uint()]
			tlv_description = tlv_ctl_resp
		else
			msgstr = ctl_messages[msgid:le_uint()]
			tlv_description = tlv_ctl_req
		end
	elseif svcid:uint() == 12 then
		mhdrtree:add_le(f.msgid_pbm, msgid)
		if indicationbit == 1 then
			msgstr = pbm_indications[msgid:le_uint()]
			tlv_description = tlv_pbm_ind
		elseif responsebit == 1 then
			msgstr = pbm_messages[msgid:le_uint()]
			tlv_description = tlv_pbm_resp
		else
			msgstr = pbm_messages[msgid:le_uint()]
			tlv_description = tlv_pbm_req
		end
	elseif svcid:uint() == 2 then
		mhdrtree:add_le(f.msgid_dms, msgid)
		if indicationbit == 1 then
			msgstr = dms_indications[msgid:le_uint()]
			tlv_description = tlv_dms_ind
		elseif responsebit == 1 then
			msgstr = dms_messages[msgid:le_uint()]
			tlv_description = tlv_dms_resp
		else
			msgstr = dms_messages[msgid:le_uint()]
			tlv_description = tlv_dms_req
		end
	elseif svcid:uint() == 36 then
		mhdrtree:add_le(f.msgid_pdc, msgid)
		if indicationbit == 1 then
			msgstr = pdc_indications[msgid:le_uint()]
			tlv_description = tlv_pdc_ind
		elseif responsebit == 1 then
			msgstr = pdc_messages[msgid:le_uint()]
			tlv_description = tlv_pdc_resp
		else
			msgstr = pdc_messages[msgid:le_uint()]
			tlv_description = tlv_pdc_req
		end
	else
		mhdrtree:add_le(f.msgid, msgid)
	end
	mhdrtree:add_le(f.msglen, msglen)
	off = off + 4

	-- TLVs, see GobiAPI/Core/QMIBuffers.h
	local msgend = off + msglen:le_uint()
	while off < msgend do
		local tlvt = buffer(off, 1)
		local tlvl = buffer(off+1, 2)
		local tlvv = buffer(off+3, tlvl:le_uint())
		local tlv_name_available = pcall(function()
			tlv_name = tlv_description[msgid:le_uint()][tlvt:uint()]
		end)
		if not tlv_name_available then
			tlv_name = "Unknown TLV"
		end
		if tlv_name == nil then
			tlv_name = "Unknown TLV"
		end
		local treesize = tlvl:le_uint() + 3
		local treename = string.format("TLV 0x%.2x %s", tlvt:uint(), tlv_name)
		local tlvtree = qmitree:add(qmi_proto, buffer(off, treesize), treename)
		tlvtree:add(f.tlvt, tlvt)
		tlvtree:add_le(f.tlvl, tlvl)
		tlvtree:add(f.tlvv, tlvv)
		off = off + treesize
	end

	-- Setup columns
	local svcstr = services[svcid:uint()] and
			services[svcid:uint()] or string.format("0x%x", svcid:uint())
	local typestr = indicationbit == 1 and
			"Indication" or responsebit == 1  and "Response" or "Request"
	msgstr = msgstr ~= nil and msgstr or string.format("0x%x", msgid:le_uint())
	pinfo.cols.protocol:append("/QMI")
	pinfo.cols.info:append(string.format(", %s %s: %s", svcstr, typestr, msgstr))
end

register_postdissector(qmi_proto)

