
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
	
	if length < 44 then return end
	if transfer_type == 3 then
		local rndistree = tree:add(rndis_data_proto, buffer(), "RNDIS")
		local rndishdrtree = rndistree:add(rndis_data_proto, buffer(0, 44), "Message Header")
		offset = offset + 44
		length = length - 44
		rndishdrtree:add_le(fields.MessageType, buffer(0, 4))
		rndishdrtree:add_le(fields.MessageLength, buffer(4, 4))
		rndishdrtree:add_le(fields.DataOffset, buffer(8, 4))
		local data_offset = buffer(8, 4):le_uint() + 8
		rndishdrtree:add_le(fields.DataLength, buffer(12, 4))
		rndishdrtree:add_le(fields.OOBDataOffset, buffer(16, 4))
		rndishdrtree:add_le(fields.OOBDataLength, buffer(20, 4))
		rndishdrtree:add_le(fields.NumOOBDataElements, buffer(24, 4))
		rndishdrtree:add_le(fields.PerPacketInfoOffset, buffer(28, 4))
		rndishdrtree:add_le(fields.PerPacketInfoLength, buffer(32, 4))
		rndishdrtree:add_le(fields.VcHandle, buffer(36, 4))
		rndishdrtree:add_le(fields.Reserved, buffer(40, 4))
		
		rndistree:add(fields.Data, buffer(44, length))
		
		Dissector.get("eth_withoutfcs"):call(buffer(data_offset):tvb(), pinfo, tree)
		return
	elseif transfer_type == 1 then
		return
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
