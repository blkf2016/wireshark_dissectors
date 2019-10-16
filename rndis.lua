
---
--- Proto declaration
---
rndis_data_proto = Proto("RNDIS", "Microsoft Remote NDIS")

local usb_transfer_type = Field.new("usb.transfer_type")
local usb_endpoint = Field.new("usb.endpoint_address")

local fields = rndis_data_proto.fields;

fields.MessageType = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.MessageType", "MessageType", base.DEC)
fields.MessageLength = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.MessageLength", "MessageLength", base.DEC)
fields.DataOffset = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.DataOffset", "DataOffset", base.DEC)
fields.DataLength = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.DataLength", "DataLength", base.DEC)
fields.OOBDataOffset = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.OOBDataOffset", "OOBDataOffset", base.DEC)
fields.OOBDataLength = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.OOBDataLength", "OOBDataLength", base.DEC)
fields.NumOOBDataElements = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.NumOOBDataElements", "NumOOBDataElements", base.DEC)
fields.PerPacketInfoOffset = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.PerPacketInfoOffset", "PerPacketInfoOffset", base.DEC)
fields.PerPacketInfoLength = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.PerPacketInfoLength", "PerPacketInfoLength", base.DEC)
fields.VcHandle = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.VcHandle", "VcHandle", base.DEC)
fields.Reserved = ProtoField.int32("REMOTE_NDIS_PACKET_MSG.Reserved", "Reserved", base.DEC)
fields.Data = ProtoField.bytes("REMOTE_NDIS_PACKET_MSG.Data", "Data")

--
-- Dissector Function
--
function rndis_data_proto.dissector(buffer, pinfo, tree)
	-- Set offset according to operating system
	local length = buffer:len()
    local transfer_type = usb_transfer_type().value
    local endpoint = usb_endpoint().value
	local offset = 0

	--print("length: " .. length)
	--print("\ttransfer_type: " .. transfer_type)
	--print("\tendpoint: " .. endpoint)
	
	if transfer_type == 3 then
		while length >= 44 do
			local msg_length = buffer(offset + 4, 4):le_uint()
			local data_offset = buffer(offset + 8, 4):le_uint() + 8
			local data_length = buffer(offset + 12, 4):le_uint()
			local rndistree = tree:add(rndis_data_proto, buffer(offset, 44), "RNDIS Packet Message")
			rndistree:add_le(fields.MessageType, buffer(offset + 0, 4))
			rndistree:add_le(fields.MessageLength, buffer(offset + 4, 4))
			rndistree:add_le(fields.DataOffset, buffer(offset + 8, 4))
			rndistree:add_le(fields.DataLength, buffer(offset + 12, 4))
			rndistree:add_le(fields.OOBDataOffset, buffer(offset + 16, 4))
			rndistree:add_le(fields.OOBDataLength, buffer(offset + 20, 4))
			rndistree:add_le(fields.NumOOBDataElements, buffer(offset + 24, 4))
			rndistree:add_le(fields.PerPacketInfoOffset, buffer(offset + 28, 4))
			rndistree:add_le(fields.PerPacketInfoLength, buffer(offset + 32, 4))
			rndistree:add_le(fields.VcHandle, buffer(offset + 36, 4))
			rndistree:add_le(fields.Reserved, buffer(offset + 40, 4))

			Dissector.get("eth_withoutfcs"):call(buffer(offset + data_offset):tvb(), pinfo, tree)
			
			length = length - msg_length
			offset = offset + msg_length
		end
	end
end

function rndis_data_proto.init()
	--usb_product = DissectorTable.get("usb.product");
	--usb_product:add(0x1d6b0104, rndis_data_proto)
	usb_table = DissectorTable.get("usb.bulk")
	usb_table:add(0x0a, rndis_data_proto)
	usb_table:add(0xffff, rndis_data_proto)
	usb_table = DissectorTable.get("usb.interrupt")
	usb_table:add(0x0a, rndis_data_proto)
	usb_table:add(0xffff, rndis_data_proto)
end

--register_postdissector(rndis_data_proto)
