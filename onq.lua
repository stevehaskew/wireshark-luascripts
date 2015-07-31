-- Steve's attempt to build an OnQ Dissector

-- Declarations
onq_proto = Proto("onq","OnQ PMS Protocol")

-- Easiest way to change the port
onq_protoport = 40000

--Add more fields as we go
F_op = ProtoField.string("onq.op","Operation")
F_rn = ProtoField.string("onq.room","Room Number")
F_gn = ProtoField.string("onq.gn","Guest Name")
F_raw = ProtoField.string("onq.raw","Raw OnQ Data")
onq_proto.fields={F_op,F_rn,F_gn,F_raw}

-- Main Dissector
function onq_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "ONQ-PMS"
	local subtree = tree:add(onq_proto,buffer(),"OnQ Protocol")

	-- Horrendous data structures
	local oqfad = {} -- All Data (Type and Data)
	local oqfd = {} -- Field Data
	local oqft = {} -- Field Type
	local oqfp = {} -- Field Position in Buffer
	local oqfl = {} -- Field Length
	local oqfc = 1 -- Field Counter

	local plen = buffer:len()
	-- i will be position counter
	local i = 0
	-- Find first pipe
	i = string.find(buffer(0,plen):string(),"|") - 1
	while i <= plen do
		-- Get everything from in front of this pipe to the end
		local restof = buffer(i+1,plen-(i+1)):string()
		-- Get position of the next pipe
		local npipe = string.find(restof,"|")
		-- Break if we're done
		if npipe == nil then
			break
		end
		-- Get the value of the bit between the pipes
		local bval = buffer(i+1,npipe-1):string()
		-- Store appropriate values
		oqfad[oqfc] = bval
		oqfd[oqfc] = buffer(i+3,npipe-3):string()
		oqft[oqfc] = buffer(i+1,2):string()
		oqfp[oqfc] = i+1
		oqfl[oqfc] = npipe-1
		-- Next field
		oqfc = oqfc + 1
		-- Move position counter to next pipe
		i = i + npipe
	end

	-- Get the operation code
	local onq_op = buffer(1,2):string()
	-- Convert it to something human readable
	local onq_op_txt = onqMessageType(onq_op)
	-- Add it to the tree
	subtree = subtree:add(F_op,buffer(1,2), onq_op,onq_op_txt)
	-- Iterate through all the fields and add them to the tree
	for ic=1,oqfc-1 do
		-- these null checks should never really happen
		if oqft[ic] == nil then
			ftype = "Null"
		else
			-- If a human-readable alternative exists, get it
			ftype = onqFieldType(oqft[ic])
		end 
		if oqfd[ic] == nil then
			fdata = "Null"
		else
			-- If we want to parse it for any reason, do so
			fdata = onqPrintable(oqft[ic],oqfd[ic])
		end
		
		-- Need to work out a cleaner way of setting field if it exists
		if oqft[ic] == "RN" then
			subtree:add(F_rn,buffer(oqfp[ic],oqfl[ic]),fdata)
		elseif oqft[ic] == "GN" then
			subtree:add(F_gn,buffer(oqfp[ic],oqfl[ic]),fdata)
		else
			subtree:add(buffer(oqfp[ic],oqfl[ic]), ftype .. " : " .. fdata)
		end
	end
	
	-- Set Info column
	onq_op_info = "OnQ " .. onq_op_txt

	-- Get all the data, except for the \002s on each end
	local onq_rawdata = buffer(1,plen-2):string()
	subtree:add(F_raw,buffer(1,plen-2),onq_rawdata)
	-- Add the string to the info column
	pinfo.cols.info:set(onq_op_info .. " - " .. onq_rawdata)
end

-- Message Type Decoding
function onqMessageType (message)
	local mtable = {["LS"]="Link Start",["LA"]="Link Alive",["LE"]="Link End",["GI"]="Guest In",["GO"]="Guest Out",["GC"]="Guest Data Change",["DR"]="Database Swap Request",["DS"]="Database Swap Start",["DE"]="Database Swap End",["NS"]="Night Audit Start",["NE"]="Night Audit End",["PR"]="Posting Request",["PS"]="Posting Simple",["PA"]="Posting Answer",["PL"]="Posting List"}
	if mtable[message] ~= nil then
		return mtable[message]
	else
		return message
	end
end

-- Field Type Decoding
function onqFieldType (message)
	local mtable = {["DA"]="Date",["TI"]="Time",["RN"]="Room Number",["GN"]="Guest Name",["GG"]="Guest Group",["G#"]="Guest ID",["GL"]="Guest Language",["GF"]="Guest First Name",["GT"]="Guest Title",["GA"]="Guest Arrival",["GD"]="Guest Departure",["RO"]="Old Room",["SO"]="Sales Outlet",["TA"]="Total Amount",["P#"]="Posting Sequence ID",["CT"]="Clear Text",["A7"]="HHonors Level, Group",["GS"]="Guest Share Flag",["NP"]="No Post Flag",["A0"]="OnQ Special Request",["GV"]="Guest VIP Status",["PM"]="Payment Method",["WS"]="Workstation ID",["PI"]="Posting Inquiry Data",["AS"]="Answer Status",["PT"]="Posting Type",["PC"]="Posting Call Type"}
	if mtable[message] ~= nil then
		return mtable[message]
	else
		return message
	end
end

-- Data Decoding
function onqPrintable (ftype,fdata)
	if ftype == "DA" then
		-- Make dates into dd/mm/yy
		return string.sub(fdata,5,6) .. "/" .. string.sub(fdata,3,4) .. "/" .. string.sub(fdata,1,2)
	elseif ftype == "GA" then
		-- Make dates into dd/mm/yy
		return string.sub(fdata,5,6) .. "/" .. string.sub(fdata,3,4) .. "/" .. string.sub(fdata,1,2)
	elseif ftype == "GD" then
		-- Make dates into dd/mm/yy
		return string.sub(fdata,5,6) .. "/" .. string.sub(fdata,3,4) .. "/" .. string.sub(fdata,1,2)
	elseif ftype == "TI" then
		-- Make times into hh:mm:ss
		return string.sub(fdata,1,2) .. ":" .. string.sub(fdata,3,4) .. ":" .. string.sub(fdata,5,6)
	elseif ftype == "AS" then
		--Decode Answer
		if fdata == "BM" then
			return("BM - Balance Mismatch")
		elseif fdata == "CD" then
			return("CD - Checkout date not today")
		elseif fdata == "IA" then
			return("IA - Invalid Account")
		elseif fdata == "NA" then
			return("NA - Night Audit")
		elseif fdata == "NF" then
			return("NF - Feature not enabled or Checkout process not running")
		elseif fdata == "NG" then
			return("NG - Guest not found")
		elseif fdata == "NM" then
			return("NM - Message/Locator not found")
		elseif fdata == "OK" then
			return("OK - Success")
		elseif fdata == "RY" then
			return("RY - Retry")
		elseif fdata == "UR" then
			return("UR - Unprocessable request")
		else
			return(fdata .. " - Unknown")
		end
	elseif ftype == "PT" then
		--Decode Answer
		if fdata == "C" then
			return("C - Direct Charge")
		elseif fdata == "M" then
			return("M - Minibar")
		else
			return(fdata .. " - Unknown")
		end
	else
		-- Otherwise return it unchanged
		return fdata
	end
end

-- Register this stuff
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(onq_protoport,onq_proto)
