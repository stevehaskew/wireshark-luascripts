local vlan_id = Field.new("vlan.id")

local function menuable_tap()
	-- Declare the window we will use
	local tw = TextWindow.new("VLAN Counter")
	local vlans = {}
	local tap = Listener.new();

	function remove()
		tap:remove();
	end
	tw:set_atclose(remove)

	function tap.packet(pinfo,tvb)
		
		local vlanid=vlan_id()
		local vlan = vlans[tostring(vlanid)] or 0

		vlans[tostring(vlanid)] = vlan + 1
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()
		tw:append("VLAN\tPackets\n");
		for vlan,num in pairs(vlans) do
			tw:append(vlan .. "\t" .. num .. "\n");
		end

	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		vlans = {}
	end
end

-- using this function we register our function
-- to be called when the user selects the Tools->Test->Packets menu
register_menu("Steve Tools/VLAN Count", menuable_tap, MENU_TOOLS_UNSORTED)