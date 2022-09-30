require "bit32"
--[[
Function  : wireshark lua configure for NewIP protocol stack
Author    : yangyanjun
Edit Date : 2022/5/27
SPDX-License-Identifier: GPL-2.0-or-later
--]]

do -- lua begin

--协议名称为NewIP，在Packet Details窗格显示为NewIP
-- create a new protocol
local nip_proto_name = "NewIP"
local nip_proto_desc = "NewIP Protocol"
local nip_proto_obj = Proto(nip_proto_name, nip_proto_desc)

--[[
NewIP协议字段定义
	ProtoField 参数：
	para1 [必选] - 字段的缩写名称（过滤器中使用的字符串）
	para2 [可选] - 字段的实际名称（出现在树中的字符串）
	para3 [可选] - 字段类型 
--]]
local _ttl        = ProtoField.uint8 (nip_proto_name .. ".ttl",        "ttl",        base.DEC)
local _total_len  = ProtoField.uint16(nip_proto_name .. ".total_len",  "total_len",  base.DEC)
local _nexthdr    = ProtoField.uint8 (nip_proto_name .. ".nexthdr",    "nexthdr",    base.DEC)
local _daddr      = ProtoField.bytes (nip_proto_name .. ".daddr",      "daddr",      base.SPACE)
local _saddr      = ProtoField.bytes (nip_proto_name .. ".saddr",      "saddr",      base.SPACE)
local _hdr_len    = ProtoField.uint8 (nip_proto_name .. ".hdr_len",    "hdr_len",    base.DEC)
local _trans_data = ProtoField.bytes (nip_proto_name .. ".trans_data", "trans_data", base.SPACE)

-- 将字段添加都协议中
nip_proto_obj.fields = {
	_ttl, 
	_total_len, 
	_nexthdr, 
	_daddr, 
	_saddr, 
	_hdr_len, 
	_trans_data
}
--获取 _trans_data 解析器
local _unknown_data_dis = Dissector.get("data")

--定义 bitmap1 子菜单
-- create a new protocol
local bitmap1_name = "bitmap1"
local bitmap1_desc = "bitmap1"
local bitmap1_obj = Proto(bitmap1_name, bitmap1_desc)

--[[
bitmap1 子菜单字段定义
	ProtoField 参数：
	para1 [必选] - 字段的缩写名称（过滤器中使用的字符串）
	para2 [可选] - 字段的实际名称（出现在树中的字符串）
	para3 [可选] - 字段类型 
--]]
local _bitmap1           = ProtoField.uint8(bitmap1_name .. ".bitmap1",           "bitmap1",           base.HEX)
local _nip_valid         = ProtoField.uint8(bitmap1_name .. ".nip_valid",         "nip_valid",         base.DEC)
local _include_ttl       = ProtoField.uint8(bitmap1_name .. ".include_ttl",       "include_ttl",       base.DEC)
local _include_total_len = ProtoField.uint8(bitmap1_name .. ".include_total_len", "include_total_len", base.DEC)
local _include_nexthdr   = ProtoField.uint8(bitmap1_name .. ".include_nexthdr",   "include_nexthdr",   base.DEC)
local _include_daddr     = ProtoField.uint8(bitmap1_name .. ".include_daddr",     "include_daddr",     base.DEC)
local _include_saddr     = ProtoField.uint8(bitmap1_name .. ".include_saddr",     "include_saddr",     base.DEC)
local _include_bitmap2   = ProtoField.uint8(bitmap1_name .. ".include_bitmap2",   "include_bitmap2",   base.DEC)

-- 将字段添加都协议中
bitmap1_obj.fields = {
	_bitmap1, _nip_valid, _include_ttl, _include_total_len, _include_nexthdr, _include_daddr, _include_saddr, _include_bitmap2
}

--定义 bitmap2 子菜单
-- create a new protocol
local bitmap2_name = "bitmap2"
local bitmap2_desc = "bitmap2"
local bitmap2_obj = Proto(bitmap2_name, bitmap2_desc)

--[[
bitmap2 子菜单字段定义
	ProtoField 参数：
	para1 [必选] - 字段的缩写名称（过滤器中使用的字符串）
	para2 [可选] - 字段的实际名称（出现在树中的字符串）
	para3 [可选] - 字段类型 
--]]
local _bitmap2         = ProtoField.uint8(bitmap2_name .. ".bitmap2",         "bitmap2",         base.HEX)
local _include_hdr_len = ProtoField.uint8(bitmap2_name .. ".include_hdr_len", "include_hdr_len", base.DEC)

-- 将字段添加都协议中
bitmap2_obj.fields = {
	_bitmap2, _include_hdr_len
}

--定义 nd icmp 子菜单
-- create a new protocol
local nd_icmp_name = "nd_icmp"
local nd_icmp_desc = "nd_icmp"
local nd_icmp_obj = Proto(nd_icmp_name, nd_icmp_desc)

--[[
nd_icmp 子菜单字段定义
	ProtoField 参数：
	para1 [必选] - 字段的缩写名称（过滤器中使用的字符串）
	para2 [可选] - 字段的实际名称（出现在树中的字符串）
	para3 [可选] - 字段类型 
--]]
local _type     = ProtoField.uint8 (nd_icmp_name .. ".type",     "type",     base.DEC)
local _code     = ProtoField.uint8 (nd_icmp_name .. ".code",     "code",     base.DEC)
local _checksum = ProtoField.uint16(nd_icmp_name .. ".checksum", "checksum", base.HEX)
local _rs_daddr = ProtoField.bytes (nd_icmp_name .. ".rs_daddr", "rs_daddr", base.SPACE)
local _mac_len  = ProtoField.uint8 (nd_icmp_name .. ".mac_len",  "mac_len",  base.DEC)
local _mac      = ProtoField.bytes (nd_icmp_name .. ".mac",      "mac",      base.SPACE)

-- 将字段添加都协议中
nd_icmp_obj.fields = {
	_type, _code, _checksum, _rs_daddr, _mac_len, _mac
}

--[[
	下面定义 newip 解析器的主函数
	第一个参数是 tvb      类型，表示的是需要此解析器解析的数据
	第二个参数是 pinfo    类型，是协议解析树上的信息，包括 UI 上的显示
	第三个参数是 treeitem 类型，表示上一级解析树
--]]
function nip_dissector(tvb, pinfo, treeitem)
	--设置一些 UI 上面的信息
	pinfo.cols.protocol:set(nip_proto_name)
	pinfo.cols.info:set(nip_proto_desc)
	
	local offset = 0
	local tvb_len = tvb:len()
	local nexthdr = 0

	-- 在上一级解析树上创建 nip 的根节点
	local nip_tree = treeitem:add(nip_proto_obj, tvb:range(tvb_len))
	
	local bitmap1 = tvb(offset, 1)	--表示从报文缓冲区0开始取1个字节
	local bitmap1_val = tvb(offset, 1):uint()
	local nip_valid			= bit.band(bit.rshift(bitmap1_val, 7), 0x00000001)	--右移 7 位 与 0x01 相与，获取 nip_valid 位
	local include_ttl		= bit.band(bit.rshift(bitmap1_val, 6), 0x00000001)	--右移 6 位 与 0x01 相与，获取 include_ttl 位
	local include_total_len	= bit.band(bit.rshift(bitmap1_val, 5), 0x00000001)	--右移 5 位 与 0x01 相与，获取 include_total_len 位
	local include_nexthdr	= bit.band(bit.rshift(bitmap1_val, 4), 0x00000001)	--右移 4 位 与 0x01 相与，获取 include_nexthdr 位
	local include_daddr		= bit.band(bit.rshift(bitmap1_val, 2), 0x00000001)	--右移 2 位 与 0x01 相与，获取 include_daddr 位
	local include_saddr		= bit.band(bit.rshift(bitmap1_val, 1), 0x00000001)	--右移 1 位 与 0x01 相与，获取 include_saddr 位
	local include_bitmap2	= bit.band(bitmap1_val, 0x00000001)					--获取 include_bitmap2 位
	offset = offset + 1	--_bitmap1 占用1字节
	
	--nip报头无效(0表示有效)
	if nip_valid ~= 0 then
		return false
	else
		--bitmap1子菜单
		local bitmap1_tree = nip_tree:add(bitmap1_obj, tvb:range(tvb_len))
		bitmap1_tree:add(_bitmap1, bitmap1)
		bitmap1_tree:add(_nip_valid, nip_valid)

		if include_ttl then
			bitmap1_tree:add(_include_ttl, include_ttl)
		end
		
		if include_total_len then
			bitmap1_tree:add(_include_total_len, include_total_len)
		end
		
		if include_nexthdr then
			bitmap1_tree:add(_include_nexthdr, include_nexthdr)
		end
		
		if include_daddr then
			bitmap1_tree:add(_include_daddr, include_daddr)
		end
		
		if include_saddr then
			bitmap1_tree:add(_include_saddr, include_saddr)
		end
		
		if include_bitmap2 then
			bitmap1_tree:add(_include_bitmap2, include_bitmap2)
		end
	end
	
	if include_bitmap2 ~= 0 then
		--bitmap2子菜单
		local bitmap2_tree = nip_tree:add(bitmap2_obj, tvb:range(tvb_len))
		local bitmap2 = tvb(offset, 1)
		local bitmap2_val = tvb(offset, 1):uint()
		local include_hdr_len = bit.band(bit.rshift(bitmap2_val, 7), 0x00000001)	--右移 7 位 与 0x01 相与，获取 include_hdr_len 位
		offset = offset + 1	--_bitmap2 占用1字节
		
		bitmap2_tree:add(_bitmap2, bitmap2)
		
		if include_hdr_len then
			bitmap2_tree:add(_include_hdr_len, include_hdr_len)
		end
	end
	
	if include_ttl then
		nip_tree:add(_ttl, tvb(offset, 1))
		offset = offset + 1	--_ttl 占用1字节
	end
	
	if include_total_len then
		nip_tree:add(_total_len, tvb(offset, 2))
		offset = offset + 2	--_total_len 占用2字节
	end
	
	if include_nexthdr then
		nexthdr = tvb(offset, 1):uint()
		nip_tree:add(_nexthdr, tvb(offset, 1))
		offset = offset + 1	--_nexthdr 占用1字节
	end
	
	if include_daddr then
		local first_addr = tvb(offset, 1):uint()
		local addr_len = get_nip_addr_len (first_addr)
		if addr_len == 0 then
			return false
		end
		nip_tree:add(_daddr, tvb(offset, addr_len))
		offset = offset + addr_len	--_daddr 占用 addr_len 字节
	end
	
	if include_saddr then
		local first_addr = tvb(offset, 1):uint()
		local addr_len = get_nip_addr_len (first_addr)
		if addr_len == 0 then
			return false
		end
		nip_tree:add(_saddr, tvb(offset, addr_len))
		offset = offset + addr_len	--_daddr 占用 addr_len 字节
	end
	
	if include_hdr_len then
		nip_tree:add(_hdr_len, tvb(offset, 1))
		offset = offset + 1	--_hdr_len 占用1字节
	end
	
	--根据next header 确定上层协议
	local trans_data = tvb(offset, tvb_len - offset)
	if (nexthdr == 177) then 
		local nd_icmp_tree = nip_tree:add(nd_icmp_obj, tvb:range(tvb_len))
		local type = tvb(offset, 1):uint()
		nd_icmp_tree:add(_type, tvb(offset, 1))
		offset = offset + 1
		nd_icmp_tree:add(_code, tvb(offset, 1))
		offset = offset + 1
		nd_icmp_tree:add(_checksum, tvb(offset, 1))
		offset = offset + 1
		if type == 1 then
			nd_icmp_tree:add(_rs_daddr, tvb(offset, 1))
			offset = offset + 1
			pinfo.cols.protocol = "ND request based NewIP"
		else
			nd_icmp_tree:add(_mac_len, tvb(offset, 1))
			offset = offset + 1
			nd_icmp_tree:add(_mac, tvb(offset, 6))
			offset = offset + 6
			pinfo.cols.protocol = "ND response based NewIP"
		end
	elseif (nexthdr == 6) then 
		Dissector.get("tcp"):call(trans_data:tvb(), pinfo, treeitem)
		pinfo.cols.protocol = "TCP based NewIP"
	elseif (nexthdr == 17) then
		Dissector.get("udp"):call(trans_data:tvb(), pinfo, treeitem)
		pinfo.cols.protocol = "UDP based NewIP"
	else
		nip_tree:add(_trans_data, trans_data)
	end
end

--[[
	下面定义 NewIP 解析器的主函数，这个函数由 wireshark调用
	第一个参数是 Tvb      类型，表示的是需要此解析器解析的数据
	第二个参数是 Pinfo    类型，是协议解析树上的信息，包括 UI 上的显示
	第三个参数是 TreeItem 类型，表示上一级解析树
--]]
function nip_proto_obj.dissector(tvb, pinfo, treeitem)
	if nip_dissector(tvb, pinfo, treeitem) then
		--valid NewIP diagram
	else
		--不是NewIP协议(其他未知协议)时，直接输出报文数据
		_unknown_data_dis:call(tvb, pinfo, treeitem)
	end
	
end


--向 wireshark 注册协议插件被调用的条件
local ipn_encap_table = DissectorTable.get("ethertype")
ipn_encap_table:add(0xEADD, nip_proto_obj)

--NewIP地址长度计算
function get_nip_addr_len (first_addr)
	if first_addr <= 0xDC then
		return 1
	elseif first_addr >= 0xDD and first_addr <= 0xF0 then
		return 2
	elseif first_addr == 0xF1 then
		return 3
	elseif first_addr == 0xF2 then
		return 5
	elseif first_addr == 0xF3 then
		return 7
	elseif first_addr == 0xF4 then
		return 9
	elseif first_addr == 0xFF then
		return 2
	else
		return 0
	end
end

end -- lua end
