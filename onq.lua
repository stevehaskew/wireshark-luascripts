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
	subtree = tree:add(onq_proto,buffer(),"OnQ Protocol")
	local nmtree = subtree:add(buffer(),"Number of messages")
	local plen = buffer:len()
	local i = 0 -- position counter - end of message
	local o = 1 -- offset
	
	i = string.find(buffer(0,plen):string(),string.char(03)) - 1
	
	-- Iterate through packet, per message
	local a = 0
	local lastmsg = ''
	local msg = string.gsub(buffer(offset,length):string(),string.char(2),"^")
	msg = string.gsub(msg,string.char(3),"$")
--	message("Whole message: " .. msg)
--	message("First message: 1 to " .. i)
	while i <= plen do
		lastmsg = onqMessageDissect(buffer,pinfo,subtree,o,i-o) -- o = offset, i-o = length
		if i == plen-1 then
			break
		end
		o = string.find(buffer(i,plen-i):string(),"\x02") + i
		local ne = string.find(buffer(i+1,plen-(i+1)):string(),"\x03")
		if ne == nil then
			-- Add message about malformity to tree
			local mdata = buffer(o,plen-o):string()
			subtree:add(buffer(o,plen-o), "Malformed message : " .. mdata)
			break
		else
			i = ne + i			
		end
--		message("Found next message from " .. o .. " to " .. i .. ". (".. buffer(o,i-o):string() ..")")
		a = a + 1
	end

	if a > 0 then
		onq_op_info = a+1 .. " OnQ Messages"
	else
		onq_op_info = lastmsg
	end
	
	nmtree:set_text("Number of messages: " .. a+1)
	
	-- Get all the data, except for the \002s on each end
	local onq_rawdata = buffer(1,plen-2):string()
	onq_rawdata=string.gsub(onq_rawdata,"\x03\x02"," - ")
	onq_rawdata=string.gsub(onq_rawdata,"\x03","")
	subtree:add(F_raw,buffer(1,plen-2),onq_rawdata)
	-- Add the string to the info column
	pinfo.cols.info:set(onq_op_info .. " - " .. onq_rawdata)
--	onqMessageDissect(buffer,pinfo,subtree,0)
end

function onqMessageDissect (buffer,pinfo,tree,offset,length)
	-- Let's see if this works...
	local subtree = tree:add(onq_proto,buffer(offset,length),"OnQ Message")

	local msg = string.gsub(buffer(offset,length):string(),string.char(2),"^")
	msg = string.gsub(msg,string.char(3),"$")
	
--	message("Now working with " .. msg ..". Offset is " .. offset .. " and length is " .. length)

	-- Horrendous data structures
	local oqfad = {} -- All Data (Type and Data)
	local oqfd = {} -- Field Data
	local oqft = {} -- Field Type
	local oqfp = {} -- Field Position in Buffer
	local oqfl = {} -- Field Length
	local oqfc = 1 -- Field Counter

	local plen = buffer:len()
	-- i will be position counter
	local i = offset
	-- Find first pipe
	i = string.find(buffer(offset,length):string(),"|")
--	message("First pipe at " .. i)
	while i <= (length-1) do
		-- Get everything from in front of this pipe to the end
--		message("Getting restof with " .. offset+i .. "," .. length-(i))
--		message("length-(offset+i)")
--		message("length " .. length .. ", offset " .. offset .. ", i " .. i)
		local restof = buffer(offset+i,length-(i)):string()
--		message("Rest of string is " .. restof)
		-- Get position of the next pipe
		local npipe = string.find(restof,"|")
--		message("Next pipe at " .. npipe)
		-- Break if we're done
		if npipe == nil then
			break
		end
		-- Get the value of the bit between the pipes
		local bval = buffer(i+1,npipe-1):string()
--		message("Got value " .. bval)
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
--		message("i value for next field is " .. i)
	end

--	message("Broken out of loop: " .. i .. " and " .. length)
	
--	message("Looking at the whole string for the opcode. offset " .. offset)
	-- Get the operation code
	local onq_op = buffer(offset,2):string()
--	message("Found " .. onq_op .. " as opcode")
	-- Convert it to something human readable
	local onq_op_txt = onqMessageType(onq_op)
	-- Add it to the tree
	subtree = subtree:add(F_op,buffer(offset,2), onq_op,onq_op_txt)
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
	return ("OnQ " .. onq_op_txt)
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
