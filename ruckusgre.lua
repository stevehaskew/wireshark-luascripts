-- Declarations
ruck_proto = Proto("RuckusGRE","Ruckus Tunnel")

--Add more fields as we go
F_data = ProtoField.string("RuckusGRE.data","Data Packet")
ruck_proto.fields={F_data}

-- Main Dissector
function ruck_proto.dissector(buffer,pinfo,tree)
	-- Basic stuff
        pinfo.cols.protocol = "RuckusGRE"
        subtree = tree:add(ruck_proto,buffer(),"RuckusGRE")

	subtree:add(F_data,buffer(0,15), "Ruckus GRE Header")

	-- Ask Wireshark to Dissect bytes 16->end as Ethernet
        local plen = buffer:len()
	Dissector.get("eth"):call(buffer(16,plen-16):tvb(),pinfo,tree)

	-- Process the info field
	local infocol = pinfo.cols.info
	local infocolstr = tostring(infocol)
	pinfo.cols.info:set("[RuckusGRE] " .. infocolstr)

end



-- Register this stuff

udp_table = DissectorTable.get("udp.port")

udp_table:add(23233,ruck_proto)

